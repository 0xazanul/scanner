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

// solidityStorageGap checks for missing __gap in upgradeable contracts
type solidityStorageGap struct{}

func (d *solidityStorageGap) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-STORAGE-GAP", Title: "Upgradeable contract missing storage gap", Severity: model.SeverityMedium}
}

func (d *solidityStorageGap) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityStorageGap) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reInherited := regexp.MustCompile(`(?i)is\s+.*Upgradeable`)
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		// quick signals: inherits OZ Upgradeable or has upgrade functions
		upgradeSignals := reInherited.FindStringIndex(content) != nil || strings.Contains(content, "upgradeTo(")
		if !upgradeSignals {
			continue
		}
		if strings.Contains(content, "uint256[50] private __gap;") || strings.Contains(content, "__gap;") {
			continue
		}
		s, e := util.FindLineRange(content, "contract ")
		findings = append(findings, model.Finding{
			RuleID:      d.Meta().ID,
			Severity:    model.SeverityMedium,
			Confidence:  0.55,
			DetectorID:  "solidity-storage-gap",
			File:        file,
			StartLine:   s,
			EndLine:     e,
			Snippet:     util.ExtractSnippet(content, s, e, 6),
			Message:     "Upgradeable contract may be missing storage gap (__gap)",
			Rationale:   "Without a storage gap, adding variables in future versions can cause layout collisions.",
			Remediation: "Add uint256[50] private __gap; in upgradeable base as per OpenZeppelin guidelines.",
			References:  []string{"OZ Upgradeable Docs"},
			Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, "storage-gap"),
		})
	}
	return findings, nil
}
