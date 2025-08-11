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

// solidityUnboundedLoops flags loops over dynamic arrays in public/external functions
type solidityUnboundedLoops struct{}

func (d *solidityUnboundedLoops) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-UNBOUNDED-LOOP", Title: "Unbounded loop over dynamic array in external function", Severity: model.SeverityMedium}
}

func (d *solidityUnboundedLoops) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityUnboundedLoops) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}
	reHeader := regexp.MustCompile(`(?m)function\s+(\w+)\s*\([^)]*\)\s*(public|external)\b[^\{]*\{`)
	reFor := regexp.MustCompile(`(?m)for\s*\(([^;]*);([^;]*);([^\)]*)\)`) // rough
	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		headers := reHeader.FindAllStringIndex(content, -1)
		for i, h := range headers {
			header := content[h[0]:h[1]]
			body := content[h[1]:]
			if i+1 < len(headers) {
				body = content[h[1]:headers[i+1][0]]
			}
			loops := reFor.FindAllStringSubmatch(body, -1)
			for _, loop := range loops {
				cond := strings.ToLower(loop[2])
				// heuristics: contains .length without explicit bound check against constant
				if strings.Contains(cond, ".length") && !regexp.MustCompile(`(?i)<\s*\d+`).MatchString(cond) {
					s, e := util.FindLineRange(content, header)
					findings = append(findings, model.Finding{
						RuleID:      d.Meta().ID,
						Severity:    model.SeverityMedium,
						Confidence:  0.55,
						DetectorID:  "solidity-unbounded-loops",
						File:        file,
						StartLine:   s,
						EndLine:     e,
						Snippet:     util.ExtractSnippet(content, s, e, 8),
						Message:     "Loop over potentially unbounded array length in external/public function",
						Rationale:   "Unbounded loops can lead to DoS due to gas exhaustion.",
						Remediation: "Bound array length or split work across transactions.",
						References:  []string{"best-practices"},
						Fingerprint: util.Fingerprint(d.Meta().ID, file, s, e, header),
					})
				}
			}
		}
	}
	return findings, nil
}
