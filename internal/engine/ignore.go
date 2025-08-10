package engine

import (
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
	return false
}

// TODO: Inline suppression: parse source file content and look for patterns
// like: // scanner:ignore RULE_ID reason="..."
