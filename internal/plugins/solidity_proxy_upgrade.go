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

// solidityProxyUpgrade finds unsafe upgrade patterns and delegatecall use without proper checks
type solidityProxyUpgrade struct{}

func (d *solidityProxyUpgrade) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-PROXY-UPGRADE", Title: "Potentially unsafe proxy/upgrade pattern", Severity: model.SeverityHigh}
}
func (d *solidityProxyUpgrade) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityProxyUpgrade) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reUpgrade := regexp.MustCompile(`(?i)function\s+(upgradeTo|upgradeToAndCall)\b`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		lc := strings.ToLower(content)
		// detect raw delegatecall usage
		if strings.Contains(lc, ".delegatecall(") {
			s, e := util.FindLineRange(lc, ".delegatecall(")
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityHigh,
				Confidence: 0.6,
				DetectorID: "solidity-proxy-upgrade",
				File:       file, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 8),
				Message:     "delegatecall detected — ensure strict target validation and access control",
				Rationale:   "delegatecall executes code in caller context; unsafe targets enable takeover",
				Remediation: "Validate implementation UUID (UUPS) or restrict calls; prefer vetted proxy patterns",
				References:  []string{"EIP-1822"},
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "delegatecall"),
			})
		}
		// detect upgrade functions without onlyOwner/onlyProxy/onlyAdmin
		if loc := reUpgrade.FindStringIndex(content); loc != nil {
			header := content[loc[0]:min(loc[0]+200, len(content))]
			hasMod := strings.Contains(header, "onlyOwner") || strings.Contains(header, "onlyProxy") || strings.Contains(header, "onlyAdmin")
			if !hasMod {
				s, e := util.FindLineRange(content, header)
				findings = append(findings, model.Finding{
					RuleID:     d.Meta().ID,
					Severity:   model.SeverityHigh,
					Confidence: 0.65,
					DetectorID: "solidity-proxy-upgrade",
					File:       file, StartLine: s, EndLine: e,
					Snippet:     util.ExtractSnippet(content, s, e, 8),
					Message:     "Upgrade function without clear access control",
					Rationale:   "Upgrades must be restricted to admin to avoid hostile implementation swaps",
					Remediation: "Add onlyOwner/onlyProxy/onlyAdmin or role checks to upgrade functions",
					Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "upgrade"),
				})
			}
		}
	}
	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
