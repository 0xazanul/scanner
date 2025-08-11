package engine

import (
	"strings"

	"github.com/xab-mack/smartscanner/internal/config"
	"github.com/xab-mack/smartscanner/internal/model"
)

// filterBySeverity removes findings below the configured severity threshold
func filterBySeverity(findings []model.Finding, cfg config.Config) []model.Finding {
	threshold := model.ParseSeverity(cfg.SeverityThreshold)
	var out []model.Finding
	for _, f := range findings {
		if model.SeverityGTE(f.Severity, threshold) {
			out = append(out, f)
		}
	}
	return out
}

// filterByPlugins keeps only findings whose RuleID is in cfg.Plugins when list is non-empty
func filterByPlugins(findings []model.Finding, cfg config.Config) []model.Finding {
	if len(cfg.Plugins) == 0 {
		return findings
	}
	allowed := map[string]struct{}{}
	for _, id := range cfg.Plugins {
		allowed[strings.TrimSpace(id)] = struct{}{}
	}
	var out []model.Finding
	for _, f := range findings {
		if _, ok := allowed[f.RuleID]; ok {
			out = append(out, f)
		}
	}
	return out
}
