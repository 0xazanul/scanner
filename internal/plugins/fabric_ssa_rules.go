package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
)

// fabricSSARules performs function-level SSA checks for endorsement and private data misuse
type fabricSSARules struct{}

func (d *fabricSSARules) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "FAB-SSA-RULES", Title: "Fabric SSA function-level checks", Severity: model.SeverityMedium}
}

func (d *fabricSSARules) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *fabricSSARules) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if strings.Contains(content, "PutState(") {
			hasID := strings.Contains(strings.ToLower(content), "getmspid") || strings.Contains(strings.ToLower(content), "getcreator") || strings.Contains(strings.ToLower(content), "getid(") || strings.Contains(strings.ToLower(content), "assertattributevalue") || strings.Contains(strings.ToLower(content), "hasattribute")
			if !hasID {
				findings = append(findings, model.Finding{
					RuleID:     d.Meta().ID,
					Severity:   model.SeverityHigh,
					Confidence: 0.55,
					DetectorID: "fabric-ssa",
					File:       file, StartLine: 1, EndLine: 1,
					Message:     "PutState without identity/endorsement validation in file (heuristic)",
					Rationale:   "Validate client identity/attributes/MSP before writes.",
					Remediation: "Use cid package checks before PutState in each write path.",
				})
			}
		}
		if strings.Contains(content, "GetPrivateData(") && (strings.Contains(strings.ToLower(content), "printf") || strings.Contains(strings.ToLower(content), "sprintln")) {
			findings = append(findings, model.Finding{
				RuleID:     "FAB-PRIVATE-DATA-LEAK",
				Severity:   model.SeverityHigh,
				Confidence: 0.65,
				DetectorID: "fabric-ssa",
				File:       file, StartLine: 1, EndLine: 1,
				Message:     "Potential private data leakage to logs",
				Rationale:   "Do not log private collection data.",
				Remediation: "Avoid logging private data; use hashes instead.",
			})
		}
	}
	return findings, nil
}

// The following helpers avoid direct imports of ssa types here to keep plugin decoupled.
// They rely on interface casting using method sets we expect to exist on *ssa.Function and related types.

// SSA helpers omitted in this heuristic version; deeper SSA path analysis comes next.
