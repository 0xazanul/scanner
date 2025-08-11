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

// solidityReentrancyPath attempts a path-style check using lightweight IR
type solidityReentrancyPath struct{}

func (d *solidityReentrancyPath) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-REENTRANCY-PATH", Title: "Reentrancy risk on path with external call before state write", Severity: model.SeverityHigh}
}
func (d *solidityReentrancyPath) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityReentrancyPath) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
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
			// crude path: any external call line less than any state write line
			risk := false
			for _, ec := range fn.ExternalCalls {
				for _, sw := range fn.StateWrites {
					if ec < sw {
						risk = true
						break
					}
				}
				if risk {
					break
				}
			}
			if !risk {
				continue
			}
			start := fn.StartsAtLine
			end := fn.StartsAtLine
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityHigh,
				Confidence: 0.7,
				DetectorID: "solidity-reentrancy-path",
				File:       file, StartLine: start, EndLine: end,
				Entity:      fn.Name,
				Snippet:     util.ExtractSnippet(content, start, end, 8),
				Message:     "Function has an external call before state update on a path (checks-effects-interactions violated)",
				Rationale:   "External call can re-enter before state is updated across a control path.",
				Remediation: "Reorder to update state before external calls, add ReentrancyGuard, or switch to pull pattern.",
				References:  []string{"SWC-107"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, start, end, fn.Name),
			})
		}
	}
	return findings, nil
}
