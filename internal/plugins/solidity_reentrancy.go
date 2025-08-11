package plugins

import (
	"context"
	"os"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/solidity"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityReentrancy flags functions where an external call occurs before a state write (heuristic)
type solidityReentrancy struct{}

func (d *solidityReentrancy) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-REENTRANCY-ORDER", Title: "External call before state update", Severity: model.SeverityHigh}
}

func (d *solidityReentrancy) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityReentrancy) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
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
		ir, err := solidity.BuildIR(file, content)
		if err != nil || ir == nil {
			continue
		}
		for _, fn := range ir.Functions {
			if strings.Contains(strings.ToLower(fn.Visibility), "view") || strings.Contains(strings.ToLower(fn.Visibility), "pure") {
				continue
			}
			if len(fn.ExternalCalls) == 0 || len(fn.StateWrites) == 0 {
				continue
			}
			// find earliest lines
			ec := minInt(fn.ExternalCalls)
			sw := minInt(fn.StateWrites)
			if ec < sw {
				start, end := fn.StartsAtLine, fn.StartsAtLine
				findings = append(findings, model.Finding{
					RuleID:     d.Meta().ID,
					Severity:   model.SeverityHigh,
					Confidence: 0.7,
					DetectorID: "solidity-reentrancy",
					File:       file,
					StartLine:  start, EndLine: end,
					Snippet:     util.ExtractSnippet(content, start, end, 8),
					Message:     "External call occurs before state update; consider checks-effects-interactions or guard",
					Rationale:   "Reentrancy may occur when external calls can re-enter before state changes",
					Remediation: "Move state updates before external calls or add ReentrancyGuard; prefer pull over push",
					References:  []string{"SWC-107"},
					Fingerprint: util.Fingerprint(d.Meta().ID, file, start, end, "reentrancy-order"),
				})
			}
		}
	}
	return findings, nil
}

func minInt(nums []int) int {
	m := nums[0]
	for _, n := range nums {
		if n < m {
			m = n
		}
	}
	return m
}
