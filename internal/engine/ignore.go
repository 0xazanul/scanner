package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/xab-mack/smartscanner/internal/config"
	"github.com/xab-mack/smartscanner/internal/model"
)

// applyIgnores filters findings based on config ignore rules and inline suppression markers
func applyIgnores(findings []model.Finding, cfg config.Config) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if isIgnored(f, cfg) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func isIgnored(f model.Finding, cfg config.Config) bool {
	for _, ig := range cfg.Ignore {
		if ig.Rule != "" && !strings.EqualFold(ig.Rule, f.RuleID) {
			continue
		}
		if ig.Path != "" {
			if !strings.HasPrefix(filepath.ToSlash(f.File), filepath.ToSlash(ig.Path)) {
				continue
			}
		}
		return true
	}
	// inline suppression
	if hasInlineSuppression(f.File, f.RuleID, f.StartLine) {
		return true
	}
	return false
}

// hasInlineSuppression looks around the finding location for a suppression comment
// Format: // scanner:ignore RULE_ID reason="..."
func hasInlineSuppression(filePath, ruleID string, startLine int) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()
	// read lines into slice (files are small for source)
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if len(lines) == 0 {
		return false
	}
	// window: 0-based indices
	from := startLine - 1 - 5
	if from < 0 {
		from = 0
	}
	to := startLine - 1 + 1
	if to >= len(lines) {
		to = len(lines) - 1
	}
	needle := "scanner:ignore " + ruleID
	for i := from; i <= to; i++ {
		if strings.Contains(lines[i], needle) {
			return true
		}
	}
	return false
}
