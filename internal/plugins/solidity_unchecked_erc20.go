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

// solidityUncheckedERC20 flags ERC20 transfer/approve/transferFrom without checking return value
type solidityUncheckedERC20 struct{}

func (d *solidityUncheckedERC20) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-UNCHECKED-ERC20", Title: "Unchecked ERC20 return value", Severity: model.SeverityMedium}
}

func (d *solidityUncheckedERC20) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityUncheckedERC20) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reCall := regexp.MustCompile(`(?m)\.(transferFrom|transfer|approve)\s*\(`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		lines := strings.Split(content, "\n")
		for i, l := range lines {
			if !reCall.MatchString(l) {
				continue
			}
			lc := strings.ToLower(l)
			checked := strings.Contains(lc, "require(") || strings.Contains(lc, "assert(") || strings.Contains(lc, ") =") || strings.Contains(lc, "bool ")
			if !checked {
				// lookahead few lines for require on result
				for look := 1; look <= 3 && i+look < len(lines); look++ {
					nl := strings.ToLower(lines[i+look])
					if strings.Contains(nl, "require(") || strings.Contains(nl, "if (") || strings.Contains(nl, ") =") {
						checked = true
						break
					}
				}
			}
			if checked {
				continue
			}
			start := i + 1
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityMedium,
				Confidence:  0.6,
				DetectorID:  "solidity-unchecked-erc20",
				File:        file,
				StartLine:   start,
				EndLine:     start,
				Snippet:     util.ExtractSnippet(content, start, start, 4),
				Message:     "ERC20 call return value not checked",
				Rationale:   "Some ERC20 tokens return false on failure; ignoring it can lead to inconsistent accounting.",
				Remediation: "Capture the boolean and require it is true, or use SafeERC20 wrappers.",
				References:  []string{"OpenZeppelin SafeERC20"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, start, start, strings.TrimSpace(l)),
			})
		}
	}
	return findings, nil
}
