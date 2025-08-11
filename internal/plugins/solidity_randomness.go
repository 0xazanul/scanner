package plugins

import (
	"context"
	"os"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityRandomness flags miner-influenced randomness sources
type solidityRandomness struct{}

func (d *solidityRandomness) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-RANDOMNESS", Title: "Weak randomness from chain attributes", Severity: model.SeverityMedium}
}
func (d *solidityRandomness) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityRandomness) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
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
		if strings.Contains(lc, "block.timestamp") || strings.Contains(lc, "blockhash(") || strings.Contains(lc, "block.number") {
			start, end := util.FindLineRange(lc, "block.")
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityMedium,
				Confidence: 0.7,
				DetectorID: "solidity-randomness",
				File:       file,
				StartLine:  start, EndLine: end,
				Snippet:     util.ExtractSnippet(content, start, end, 6),
				Message:     "Use of miner-influenced randomness source",
				Rationale:   "Miners can influence timestamps/blockhash; outcomes may be manipulated",
				Remediation: "Use Chainlink VRF or commit-reveal schemes instead of chain attributes",
				References:  []string{"SWC-120"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, start, end, "randomness"),
			})
		}
	}
	return findings, nil
}
