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

// solidityUninitializedStorage detects local uninitialized storage references (SWC-109)
type solidityUninitializedStorage struct{}

func (d *solidityUninitializedStorage) Meta() model.RuleMeta {
	return model.RuleMeta{ID: "SOL-UNINIT-STORAGE", Title: "Uninitialized storage reference in local variable", Severity: model.SeverityHigh}
}

func (d *solidityUninitializedStorage) Analyze(ctx context.Context, req model.ScanRequest) ([]model.Finding, error) {
	return d.AnalyzeV2(ctx, nil, req)
}

func (d *solidityUninitializedStorage) AnalyzeV2(ctx context.Context, pctx any, req model.ScanRequest) ([]model.Finding, error) {
	var findings []model.Finding
	pc, _ := pctx.(*analysis.ProjectContext)
	if pc == nil {
		return findings, nil
	}

	// Heuristic regex: local declaration of struct/array without memory/calldata/storage keyword
	// e.g., MyStruct s; or uint256[] a; inside function body
	reFunc := regexp.MustCompile(`(?m)function\s+\w+\s*\([^)]*\)\s*[^{]*{`)
	reDecl := regexp.MustCompile(`(?m)^(\s)*(\w+\s*(\[\s*\])+)\s+(\w+)\s*;|^(\s)*(\w+)\s+(\w+)\s*;`)

	for _, file := range pc.SolidityFiles {
		content := pc.FileContents[file]
		if content == "" {
			b, _ := os.ReadFile(file)
			content = string(b)
		}
		// Split naïvely per function to reduce FPs at contract/global scope
		funcLocs := reFunc.FindAllStringIndex(content, -1)
		for i, loc := range funcLocs {
			header := content[loc[0]:loc[1]]
			body := content[loc[1]:]
			if i+1 < len(funcLocs) {
				body = content[loc[1]:funcLocs[i+1][0]]
			}
			// search declarations in body
			lines := strings.Split(body, "\n")
			for li, line := range lines {
				l := strings.TrimSpace(line)
				if l == "" {
					continue
				}
				// skip if contains memory/calldata/storage keywords
				if strings.Contains(l, " memory ") || strings.HasSuffix(l, " memory;") || strings.Contains(l, " calldata ") || strings.Contains(l, " storage ") {
					continue
				}
				// skip obvious value types (uint, int, bool, address, bytes, string) without []
				low := strings.ToLower(l)
				if regexp.MustCompile(`^(uint|int|bool|address|bytes|string)(\s|\[)`).MatchString(low) {
					// if it's dynamic array of value type without memory: still risky
					if strings.Contains(low, "[") {
						// treat as potential issue
					} else {
						continue
					}
				}
				if m := reDecl.FindStringSubmatch(line); m != nil {
					// require a subsequent write-like usage to reduce FPs
					// look ahead a few lines for assignments to fields or index usage
					suspicious := false
					for look := 1; look <= 5 && li+look < len(lines); look++ {
						nl := strings.TrimSpace(lines[li+look])
						if strings.Contains(nl, ".") || strings.Contains(nl, "[") || strings.Contains(nl, "=") {
							suspicious = true
							break
						}
					}
					if !suspicious {
						continue
					}
					// compute absolute line numbers approx
					startOffset, _ := util.FindLineRange(content, header)
					start := startOffset + li + 1
					end := start
					findings = append(findings, model.Finding{
						RuleID:      d.Meta().ID,
						Severity:    model.SeverityHigh,
						Confidence:  0.65,
						DetectorID:  "solidity-uninit-storage",
						File:        file,
						StartLine:   start,
						EndLine:     end,
						Snippet:     util.ExtractSnippet(content, start, end, 8),
						Message:     "Local variable of reference type declared without memory/calldata — defaults to storage",
						Rationale:   "Uninitialized storage reference can overwrite state when written to.",
						Remediation: "Declare as memory or calldata (e.g., MyStruct memory s) unless an explicit storage reference is intended.",
						References:  []string{"SWC-109"},
						Fingerprint: util.Fingerprint(d.Meta().ID, file, start, end, strings.TrimSpace(line)),
					})
				}
			}
		}
	}
	return findings, nil
}
