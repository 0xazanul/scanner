package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

type goFabricHeuristics struct{}

func (g *goFabricHeuristics) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "FAB-BASE-000", Title: "Fabric chaincode heuristic checks", Severity: model.SeverityLow}
}

func (g *goFabricHeuristics) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return g.AnalyzeV2(ctx, nil, req)
}

func (g *goFabricHeuristics) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	_ = filepath.WalkDir(req.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		if strings.Contains(content, "PutState(") && !strings.Contains(content, "GetState(") {
			s, e := util.FindLineRange(content, "PutState(")
			findings = append(findings, model.Finding{
				RuleID:     "FAB-PUTSTATE-NO-GETSTATE",
				Severity:   model.SeverityMedium,
				Confidence: 0.6,
				DetectorID: "fabric-heuristics",
				File:       path, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 8),
				Message:     "PutState usage without prior GetState validation (heuristic)",
				Rationale:   "Write without read/validate can break invariants",
				Remediation: "Fetch existing state with GetState and validate identity/endorsement before PutState.",
				Fingerprint: util.Fingerprint("FAB-PUTSTATE-NO-GETSTATE", path, s, e, "PutState"),
			})
		}
		if strings.Contains(content, "GetPrivateData(") && strings.Contains(strings.ToLower(content), "fmt.printf") {
			s, e := util.FindLineRange(content, "GetPrivateData(")
			findings = append(findings, model.Finding{
				RuleID:     "FAB-PRIVATE-DATA-LOG",
				Severity:   model.SeverityHigh,
				Confidence: 0.7,
				DetectorID: "fabric-heuristics",
				File:       path, StartLine: s, EndLine: e,
				Snippet:     util.ExtractSnippet(content, s, e, 8),
				Message:     "Potential leakage: printing private data",
				Rationale:   "Private collection data should not be logged",
				Remediation: "Avoid logging private collection contents; use GetPrivateDataHash for public disclosure.",
				Fingerprint: util.Fingerprint("FAB-PRIVATE-DATA-LOG", path, s, e, "GetPrivateData"),
			})
		}
		return nil
	})
	return findings, nil
}
