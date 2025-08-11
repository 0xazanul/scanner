package plugins

import (
	"context"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
)

// fabricFunctionRules: function-level heuristic checks for PutState identity validation and private data misuse
type fabricFunctionRules struct{}

func (d *fabricFunctionRules) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "FAB-FUNC-RULES", Title: "Fabric function-level heuristics", Severity: model.SeverityMedium}
}
func (d *fabricFunctionRules) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *fabricFunctionRules) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	files := map[string]string{}
	if pc != nil {
		for f, c := range pc.FileContents {
			if strings.HasSuffix(strings.ToLower(f), ".go") {
				files[f] = c
			}
		}
	}
	// Load content for Go files not in cache if scanning path
	if len(files) == 0 {
		// noop: rely on pc
	}
	reHeader := regexp.MustCompile(`(?m)^\s*func\s+(\([^)]*\)\s*)?[A-Za-z_][\w]*\s*\([^)]*\)\s*\{`)
	for file, content := range files {
		idxs := reHeader.FindAllStringIndex(content, -1)
		for i, span := range idxs {
			start := span[0]
			end := len(content)
			if i+1 < len(idxs) {
				end = idxs[i+1][0]
			}
			fn := content[start:end]
			// Heuristic: contains PutState but lacks identity checks
			if strings.Contains(fn, "PutState(") {
				lc := strings.ToLower(fn)
				hasID := strings.Contains(lc, "getmspid") || strings.Contains(lc, "getcreator") || strings.Contains(lc, "assertattributevalue") || strings.Contains(lc, "hasattribute") || strings.Contains(lc, "getid(")
				if !hasID {
					// compute line number
					prefix := content[:start]
					startLine := strings.Count(prefix, "\n") + 1
					findings = append(findings, model.Finding{
						RuleID:     d.Meta().ID,
						Severity:   model.SeverityHigh,
						Confidence: 0.6,
						DetectorID: "fabric-func",
						File:       file, StartLine: startLine, EndLine: startLine,
						Message:     "PutState without identity/endorsement checks in function",
						Rationale:   "Endorsement adherence should validate client identity/attributes/MSP per write path.",
						Remediation: "Use cid package (GetID/GetMSPID/AssertAttributeValue) before PutState.",
					})
				}
			}
			// Private data misuse in function
			if strings.Contains(fn, "GetPrivateData(") && (strings.Contains(strings.ToLower(fn), "printf") || strings.Contains(strings.ToLower(fn), "sprintln")) {
				prefix := content[:start]
				startLine := strings.Count(prefix, "\n") + 1
				findings = append(findings, model.Finding{
					RuleID:     "FAB-PRIVATE-DATA-LEAK",
					Severity:   model.SeverityHigh,
					Confidence: 0.7,
					DetectorID: "fabric-func",
					File:       file, StartLine: startLine, EndLine: startLine,
					Message:     "Private data may be logged in this function",
					Rationale:   "Avoid logging or emitting private collection values.",
					Remediation: "Remove logs or log only hash via GetPrivateDataHash.",
				})
			}
		}
	}
	return findings, nil
}
