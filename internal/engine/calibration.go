package engine

import "github.com/xab-mack/smartscanner/internal/model"

// calibrateFindings merges duplicates and increases confidence when corroborated
func calibrateFindings(in []model.Finding) []model.Finding {
	type key struct {
		file  string
		start int
		rule  string
	}
	groups := map[key][]model.Finding{}
	for _, f := range in {
		k := key{file: f.File, start: f.StartLine, rule: f.RuleID}
		groups[k] = append(groups[k], f)
	}
	var out []model.Finding
	for _, fs := range groups {
		if len(fs) == 1 {
			out = append(out, fs[0])
			continue
		}
		merged := fs[0]
		maxSev := merged.Severity
		totalConf := 0.0
		for _, f := range fs {
			if model.SeverityGTE(f.Severity, maxSev) {
				maxSev = f.Severity
			}
			if f.Confidence > 0 {
				totalConf += f.Confidence
			}
		}
		merged.Severity = maxSev
		avg := totalConf / float64(len(fs))
		merged.Confidence = avg + 0.1
		if merged.Confidence > 0.99 {
			merged.Confidence = 0.99
		}
		out = append(out, merged)
	}
	return out
}
