package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"golang.org/x/tools/go/ssa"
)

// fabricSSAStrict: function-level SSA traversal to check PutState paths include identity/endorsement checks
type fabricSSAStrict struct{}

func (d *fabricSSAStrict) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "FAB-SSA-STRICT", Title: "Fabric SSA endorsement checks (function-level)", Severity: model.SeverityHigh}
}
func (d *fabricSSAStrict) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *fabricSSAStrict) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil || pc.SSAProgram == nil || len(pc.SSAPackages) == 0 {
		return findings, nil
	}
	fset := pc.SSAProgram.Fset
	for _, pkg := range pc.SSAPackages {
		for _, mem := range pkg.Members {
			fn, ok := mem.(*ssa.Function)
			if !ok || fn.Blocks == nil {
				continue
			}
			hasPut := false
			hasID := false
			leaks := false
			for _, b := range fn.Blocks {
				for _, ins := range b.Instrs {
					call, ok := ins.(interface{ Common() *ssa.CallCommon })
					if !ok || call.Common() == nil {
						continue
					}
					name := lowerCallName(call.Common())
					if strings.Contains(name, "putstate") {
						hasPut = true
					}
					if strings.Contains(name, "getmspid") || strings.Contains(name, "getcreator") || strings.Contains(name, "getid(") || strings.Contains(name, "assertattributevalue") || strings.Contains(name, "hasattribute") {
						hasID = true
					}
					if strings.Contains(name, "getprivatedata") && functionMentions(fn, "printf", "sprintln") {
						leaks = true
					}
				}
			}
			if hasPut && !hasID {
				pos := fset.Position(fn.Pos())
				findings = append(findings, model.Finding{
					RuleID:     d.Meta().ID,
					Severity:   model.SeverityHigh,
					Confidence: 0.7,
					DetectorID: "fabric-ssa-strict",
					File:       pos.Filename,
					StartLine:  pos.Line, EndLine: pos.Line,
					Message:     "PutState without identity/endorsement validation in function",
					Rationale:   "Write paths should validate client identity/attributes/MSP.",
					Remediation: "Add cid-based checks (GetID/GetMSPID/AssertAttributeValue) before writes.",
				})
			}
			if leaks {
				pos := fset.Position(fn.Pos())
				findings = append(findings, model.Finding{
					RuleID:     "FAB-PRIVATE-DATA-LEAK",
					Severity:   model.SeverityHigh,
					Confidence: 0.75,
					DetectorID: "fabric-ssa-strict",
					File:       pos.Filename,
					StartLine:  pos.Line, EndLine: pos.Line,
					Message:     "Potential private data leakage to logs",
					Rationale:   "Avoid logging private collection data.",
					Remediation: "Use GetPrivateDataHash or remove logs.",
				})
			}
		}
	}
	return findings, nil
}

func lowerCallName(c *ssa.CallCommon) string {
	if c == nil {
		return ""
	}
	if c.StaticCallee() != nil {
		return strings.ToLower(c.StaticCallee().Name())
	}
	return strings.ToLower(c.Value.String())
}

func functionMentions(fn *ssa.Function, needles ...string) bool {
	body := fn.String()
	lb := strings.ToLower(body)
	for _, n := range needles {
		if strings.Contains(lb, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
