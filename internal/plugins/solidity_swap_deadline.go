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

// soliditySwapDeadline checks swaps without deadline argument or with zero
type soliditySwapDeadline struct{}

func (d *soliditySwapDeadline) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-SWAP-DEADLINE", Title: "Swap call without deadline protection", Severity: model.SeverityMedium}
}

func (d *soliditySwapDeadline) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *soliditySwapDeadline) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	// Look for common router function names and check for 'deadline' or last arg zero
	reSwap := regexp.MustCompile(`(?i)\.(swapExactTokensForTokens|swapExactETHForTokens|swapExactTokensForETH|swapETHForExactTokens|swapTokensForExactTokens)\s*\(([^)]*)\)`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		matches := reSwap.FindAllStringSubmatchIndex(content, -1)
		for _, m := range matches {
			args := content[m[4]:m[5]]
			lowArgs := strings.ToLower(args)
			// simple heuristic: require 'deadline' identifier or a non-zero trailing arg
			hasDeadlineIdent := strings.Contains(lowArgs, "deadline")
			// check trailing argument zero
			trailing := strings.TrimSpace(args)
			zeroDeadline := strings.HasSuffix(trailing, ", 0") || strings.HasSuffix(trailing, ",0") || trailing == "0"
			if !hasDeadlineIdent || zeroDeadline {
				s, e := util.FindLineRange(content, content[m[0]:m[1]])
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityMedium,
					Confidence:  0.55,
					DetectorID:  "solidity-swap-deadline",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 6),
					Message:     "Swap call may lack deadline/expiry protection",
					Rationale:   "Missing deadline allows transactions to be mined later and be sandwiched.",
					Remediation: "Pass a deadline timestamp reasonably in the future and check slippage as well.",
					References:  []string{"DEX best practices"},
					Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "swap-deadline"),
				})
			}
		}
	}
	return findings, nil
}
