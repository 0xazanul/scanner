package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
)

// fabricIdentityEndorsement: heuristic SSA-based checks around PutState without identity/endorsement validation
type fabricIdentityEndorsement struct{}

func (d *fabricIdentityEndorsement) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "FAB-IDENTITY-ENDORSEMENT", Title: "Missing identity/endorsement validation before PutState", Severity: model.SeverityHigh}
}

func (d *fabricIdentityEndorsement) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *fabricIdentityEndorsement) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil || pc.SSAProgram == nil {
		return findings, nil
	}
	// Lightweight approach: scan file contents for presence of PutState in functions without cid/identity checks nearby
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if !strings.Contains(content, "PutState(") {
			continue
		}
		// identity related hints
		hasID := strings.Contains(content, "cid.GetID(") || strings.Contains(content, "GetCreator(") || strings.Contains(strings.ToLower(content), "hasattribute")
		hasMSP := strings.Contains(strings.ToLower(content), "getmspid") || strings.Contains(strings.ToLower(content), "assertattributevalue")
		if !(hasID || hasMSP) {
			findings = append(findings, model.Finding{
				RuleID:     d.Meta().ID,
				Severity:   model.SeverityHigh,
				Confidence: 0.55,
				DetectorID: "fabric-identity-endorsement",
				File:       file,
				StartLine:  1, EndLine: 1,
				Message:     "PutState detected without nearby identity/endorsement validation (heuristic)",
				Rationale:   "Chaincode should validate client identity/attributes and endorsement expectations before writes",
				Remediation: "Validate client MSP/ID/attributes via cid package and ensure endorsement policy is respected.",
			})
		}
	}
	return findings, nil
}
