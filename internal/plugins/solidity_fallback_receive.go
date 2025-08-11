package plugins

import (
	"context"
	"os"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityFallbackReceive flags payable fallback/receive functions lacking guards/accounting
type solidityFallbackReceive struct{}

func (d *solidityFallbackReceive) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-FALLBACK-RECEIVE", Title: "Payable fallback/receive without safeguards", Severity: model.SeverityMedium}
}
func (d *solidityFallbackReceive) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityFallbackReceive) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		lc := strings.ToLower(content)
		// naive detect payable fallback/receive
		if strings.Contains(lc, "fallback() external payable") || strings.Contains(lc, "receive() external payable") {
			s, e := util.FindLineRange(lc, "external payable")
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityMedium,
				Confidence: 0.6,
				DetectorID: "solidity-fallback-receive",
				File:       file, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Payable fallback/receive present; ensure safeguards against accidental ether and gas griefing",
				Rationale:   "Unprotected payable functions can receive ether unintentionally and be abused",
				Remediation: "Consider reverting in fallback/receive or implement explicit accounting and limits.",
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "fallback/receive"),
			})
		}
	}
	return findings, nil
}
