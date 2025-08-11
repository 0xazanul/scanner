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

// solidityOwnerRisk inspects onlyOwner/admin functions performing external calls or fund movements
type solidityOwnerRisk struct{}

func (d *solidityOwnerRisk) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-OWNER-RISK", Title: "Powerful onlyOwner/admin function", Severity: model.SeverityMedium}
}

func (d *solidityOwnerRisk) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityOwnerRisk) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?[^\{]*\b(onlyOwner|onlyRole\([^)]*\)|onlyAdmin)\b[^\{]*\{`)
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
			bl := strings.ToLower(body)
			// risky if external calls or value transfers or critical var writes
			risky := strings.Contains(bl, ".call(") || strings.Contains(bl, ".call{") || strings.Contains(bl, ".transfer(") || strings.Contains(bl, ".send(")
			risky = risky || regexp.MustCompile(`(?m)\b(owner|admin|oracle|implementation|proxy|router)\s*=`).FindStringIndex(body) != nil
			if !risky {
				continue
			}
			s, e := util.FindLineRange(content, header)
			fnName := ""
			if m := regexp.MustCompile(`function\s+(\w+)`).FindStringSubmatch(header); len(m) >= 2 {
				fnName = m[1]
			}
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityMedium,
				Confidence:  0.6,
				DetectorID:  "solidity-owner-risk",
				File:        file,
				Entity:      fnName,
				StartLine:   s,
				EndLine:     e,
				Snippet:     util.ExtractSnippet(content, s, e, 8),
				Message:     "onlyOwner/admin function performs powerful external actions",
				Rationale:   "Centralized authority over transfers or critical pointers increases risk.",
				Remediation: "Restrict via multisig/timelock and document procedures; limit scope of such functions.",
				References:  []string{"governance-best-practices"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, fnName),
			})
		}
	}
	return findings, nil
}
