package plugins

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityMsgValueChecks flags payable functions that ignore msg.value (no accounting, no refund, no emit)
type solidityMsgValueChecks struct{}

func (d *solidityMsgValueChecks) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-MSGVALUE-CHECKS", Title: "Payable function ignores msg.value", Severity: model.SeverityMedium}
}

func (d *solidityMsgValueChecks) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityMsgValueChecks) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?[^\{]*payable[^\{]*\{`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		headers := reHeader.FindAllStringIndex(content, -1)
		for i, h := range headers {
			header := content[h[0]:h[1]]
			body := content[h[1]:]
			if i+1 < len(headers) {
				body = content[h[1]:headers[i+1][0]]
			}
			// if body does not reference msg.value and has no storage writes or emits, flag
			bl := strings.ToLower(body)
			usesValue := strings.Contains(bl, "msg.value")
			hasEmit := strings.Contains(bl, "emit ")
			hasWrite := regexp.MustCompile(`(?m)\b[_a-zA-Z][\w]*\s*=`).FindStringIndex(body) != nil
			if !usesValue && !hasEmit && !hasWrite {
				s, e := util.FindLineRange(content, header)
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityMedium,
					Confidence:  0.65,
					DetectorID:  "solidity-msgvalue-checks",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 8),
					Message:     "Payable function does not account for msg.value",
					Rationale:   "ETH sent to the function may be unintentionally accepted without accounting or refund.",
					Remediation: "Validate msg.value, account for it in state, emit events, or revert if not expected.",
					References:  []string{"best-practices"},
					Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, header),
				})
			}
		}
	}
	return findings, nil
}
