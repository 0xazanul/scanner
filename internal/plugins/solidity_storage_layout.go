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

// solidityStorageLayout warns about missing storage gaps and potential storage layout hazards in upgradeable contracts
type solidityStorageLayout struct{}

func (d *solidityStorageLayout) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-STORAGE-LAYOUT", Title: "Potential storage layout hazards in upgradeable contract", Severity: model.SeverityMedium}
}
func (d *solidityStorageLayout) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityStorageLayout) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reUpgrade := regexp.MustCompile(`(?i)function\s+(upgradeTo|upgradeToAndCall)\b`)
	reGap := regexp.MustCompile(`__gap\s*\[(\d+)\]`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		// If upgrade functions exist or OZ upgradeable import present, but no __gap declared, warn
		isUpgradeable := reUpgrade.MatchString(content) || strings.Contains(content, "openzeppelin") && strings.Contains(strings.ToLower(content), "upgradeable")
		hasGap := reGap.MatchString(content)
		if isUpgradeable && !hasGap {
			s, e := util.FindLineRange(content, "contract ")
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityMedium,
				Confidence: 0.55,
				DetectorID: "solidity-storage-layout",
				File:       file, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 6),
				Message:     "Upgradeable contract without reserved storage gap",
				Rationale:   "Adding variables in future versions can cause storage collisions without reserved gaps",
				Remediation: "Follow OZ pattern with reserved storage gaps (e.g., uint256[50] private __gap;)",
				Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "storage-gap"),
			})
		}
	}
	return findings, nil
}
