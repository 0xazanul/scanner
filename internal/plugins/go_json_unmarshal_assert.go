package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goJSONUnmarshalAssert flags json.Unmarshal into interface{} followed by unchecked type assertions
type goJSONUnmarshalAssert struct{}

func (d *goJSONUnmarshalAssert) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-JSON-UNSAFE-ASSERT", Title: "Unchecked type assertions after json.Unmarshal", Severity: model.SeverityMedium}
}

func (d *goJSONUnmarshalAssert) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goJSONUnmarshalAssert) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if strings.Contains(content, "json.Unmarshal(") && strings.Contains(content, "interface{}") {
			// look for ")" type assertion without ok variant
			if strings.Contains(content, ".(map[string]interface{})") && !strings.Contains(content, ", ok :=") {
				s, e := util.FindLineRange(content, "json.Unmarshal(")
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityMedium,
					Confidence:  0.5,
					DetectorID:  "go-json-unsafe-assert",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 6),
					Message:     "Unchecked type assertion after json.Unmarshal",
					Rationale:   "Type assertions without ok check can panic on malformed input.",
					Remediation: "Use v, ok := x.(T) and handle the false branch.",
				})
			}
		}
	}
	return findings, nil
}
