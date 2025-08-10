package plugins

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

type solidityUncheckedCalls struct{}

func (d *solidityUncheckedCalls) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-UNCHECKED-LOWLEVEL", Title: "Unchecked low-level calls", Severity: model.SeverityHigh}
}

func (d *solidityUncheckedCalls) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityUncheckedCalls) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	// Regex to find low-level calls: .call(, .call{, .delegatecall(, .staticcall(, .send(
	re := regexp.MustCompile(`\.(call\{|call\(|delegatecall\(|staticcall\(|send\()`) // basic
	for _, path := range discoverSolFiles(pc, req.Path) {
		content := readContent(pc, path)
		if content == "" {
			continue
		}
		// scan line by line
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			locs := re.FindAllStringIndex(line, -1)
			if len(locs) == 0 {
				continue
			}
			// heuristic: if same line contains "require(" or assigned to variables like (success, ), or checks
			lc := strings.ToLower(line)
			checked := strings.Contains(lc, "require(") || strings.Contains(lc, "assert(") || strings.Contains(lc, "revert(") || strings.Contains(lc, ") =") || strings.Contains(lc, "bool ")
			if checked {
				continue
			}
			start, end := i+1, i+1
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityHigh,
				Confidence:  0.65,
				DetectorID:  "solidity-unchecked-calls",
				File:        path,
				StartLine:   start,
				EndLine:     end,
				Snippet:     util.ExtractSnippet(content, start, end, 6),
				Message:     "Low-level call without checking return value",
				Rationale:   "call/delegatecall/staticcall/send return success flag that must be handled",
				Remediation: "Capture the boolean return and handle failures (require/if/rollback)",
				References:  []string{"SWC-104"},
				Fingerprint: util.Fingerprint(d.Meta().ID, path, start, end, strings.TrimSpace(line)),
			})
		}
	}
	return findings, nil
}

func discoverSolFiles(pc *analysis.ProjectContext, root string) []string {
	if pc != nil && len(pc.SolidityFiles) > 0 {
		return pc.SolidityFiles
	}
	return []string{filepath.ToSlash(root)}
}

func readContent(pc *analysis.ProjectContext, path string) string {
	if pc != nil {
		if c, ok := pc.FileContents[path]; ok {
			return c
		}
	}
	return ""
}
