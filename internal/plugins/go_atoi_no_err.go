package plugins

import (
	"context"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// goAtoiNoErr flags strconv.Atoi without error handling
type goAtoiNoErr struct{}

func (d *goAtoiNoErr) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "GO-ATOI-NO-ERR", Title: "strconv.Atoi used without error handling", Severity: model.SeverityMedium}
}

func (d *goAtoiNoErr) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *goAtoiNoErr) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	for file, content := range pc.FileContents {
		if !strings.HasSuffix(strings.ToLower(file), ".go") {
			continue
		}
		if strings.Contains(content, "strconv.Atoi(") {
			// look for err checks nearby
			l := strings.ToLower(content)
			if !strings.Contains(l, "if err != nil") {
				s, e := util.FindLineRange(content, "strconv.Atoi(")
				findings = append(findings, model.Finding{
					RuleID:      d.Meta().ID,
					Severity:    model.SeverityMedium,
					Confidence:  0.5,
					DetectorID:  "go-atoi-no-err",
					File:        file,
					StartLine:   s,
					EndLine:     e,
					Snippet:     util.ExtractSnippet(content, s, e, 6),
					Message:     "strconv.Atoi used without error check",
					Rationale:   "Ignoring conversion errors can cause incorrect logic or panics.",
					Remediation: "Capture the error and handle failure path appropriately.",
				})
			}
		}
	}
	return findings, nil
}
