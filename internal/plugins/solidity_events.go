package plugins

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/analysis"
	"github.com/xab-mack/smartscanner/internal/model"
	"github.com/xab-mack/smartscanner/internal/util"
)

// Heuristic detector for missing events on critical state changes
type solidityMissingEvents struct{}

func (d *solidityMissingEvents) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-MISSING-EVENT", Title: "State change without event emission", Severity: model.SeverityMedium}
}

func (d *solidityMissingEvents) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityMissingEvents) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	for _, path := range solFiles(pc, req.Path) {
		content := fileContent(pc, path)
		if content == "" {
			b, _ := os.ReadFile(path)
			content = string(b)
		}
		// collect likely state variable names at top level (very heuristic)
		// matches lines like: uint256 public totalSupply; address private owner;
		varNames := collectStateVars(content)
		if len(varNames) == 0 {
			continue
		}
		// split by function bodies roughly
		funcs := splitFunctions(content)
		for _, fn := range funcs {
			if !strings.Contains(fn, "{") {
				continue
			}
			body := fn[strings.Index(fn, "{")+1:]
			// identify assignments to state vars
			changed := false
			for _, name := range varNames {
				if regexp.MustCompile(`(?m)\b`+regexp.QuoteMeta(name)+`\s*=`).FindStringIndex(body) != nil {
					changed = true
					break
				}
			}
			if !changed {
				continue
			}
			if strings.Contains(body, "emit ") {
				continue
			}
			// compute line range from function header occurrence
			start, end := util.FindLineRange(content, fn)
			findings = append(findings, model.Finding{
				RuleID:      d.Meta().ID,
				Severity:    model.SeverityMedium,
				Confidence:  0.6,
				DetectorID:  "solidity-missing-events",
				File:        path,
				StartLine:   start,
				EndLine:     end,
				Snippet:     util.ExtractSnippet(content, start, end, 10),
				Message:     "State change without corresponding event emission",
				Rationale:   "Critical state updates should emit events for auditability and off-chain consumers",
				Remediation: "Emit an event when updating critical state variables; include relevant parameters.",
				References:  []string{"SWC-1010"},
				Fingerprint: util.Fingerprint(d.Meta().ID, path, start, end, "missing-emit"),
			})
		}
	}
	return findings, nil
}

func solFiles(pc *analysis.ProjectContext, root string) []string {
	if pc != nil && len(pc.SolidityFiles) > 0 {
		return pc.SolidityFiles
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".sol") {
			out = append(out, path)
		}
		return nil
	})
	return out
}

func fileContent(pc *analysis.ProjectContext, path string) string {
	if pc != nil {
		if c, ok := pc.FileContents[path]; ok {
			return c
		}
	}
	return ""
}

func collectStateVars(content string) []string {
	lines := strings.Split(content, "\n")
	var names []string
	re := regexp.MustCompile(`(?m)^(\s)*(address|uint|uint256|int|bool|string|bytes)(\s+\w+)?\s+(public|private|internal|external)?\s+(\w+)\s*;`)
	for _, l := range lines {
		m := re.FindStringSubmatch(l)
		if len(m) >= 6 {
			names = append(names, m[5])
		}
	}
	return names
}

func splitFunctions(content string) []string {
	// naive split on 'function ' and include the header and body up to next 'function '
	parts := strings.Split(content, "function ")
	var out []string
	for i := 1; i < len(parts); i++ {
		chunk := parts[i]
		// stop at next function or end
		next := strings.Index(chunk, "\nfunction ")
		if next > 0 {
			chunk = chunk[:next]
		}
		out = append(out, "function "+chunk)
	}
	return out
}
