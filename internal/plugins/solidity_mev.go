package plugins

import (
	"context"
	"os"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// solidityMEV flags potential front-running patterns (heuristics)
type solidityMEV struct{}

func (d *solidityMEV) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-MEV", Title: "Potential MEV/front-running susceptibility", Severity: model.SeverityMedium}
}
func (d *solidityMEV) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityMEV) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
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
		// Heuristic 1: approve without decreaseAllowance/permit guidance
		if strings.Contains(lc, "approve(") && !strings.Contains(lc, "decreaseallowance") {
			s, e := util.FindLineRange(lc, "approve(")
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityMedium,
				Confidence: 0.5,
				DetectorID: "solidity-mev",
				File:       file, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Token approve pattern may be front-runnable (race to spend)",
				Rationale:   "Changing allowance from non-zero to non-zero allows race conditions",
				Remediation: "Use decreaseAllowance to zero first or EIP-2612 permit pattern.",
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "approve"),
			})
		}
		// Heuristic 2: no slippage checks for swaps (e.g., Uniswap) when calling router.swap without setting minOut
		if strings.Contains(lc, "swapexacttokensfor") && !strings.Contains(lc, "minimumamountout") && !strings.Contains(lc, "amountoutmin") {
			s, e := util.FindLineRange(lc, "swapexacttokensfor")
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityMedium,
				Confidence: 0.5,
				DetectorID: "solidity-mev",
				File:       file, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Swap without explicit slippage protection (amountOutMin)",
				Rationale:   "Transactions without slippage bounds are vulnerable to sandwich attacks",
				Remediation: "Pass reasonable amountOutMin based on user tolerance and on-chain TWAP.",
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "swap"),
			})
		}
	}
	return findings, nil
}
