package engine

import (
	"encoding/json"
	"os"
	"time"

	"github.com/xab-mack/smartscanner/internal/model"
)

type baseline struct {
	GeneratedAt  time.Time       `json:"generatedAt"`
	Fingerprints map[string]bool `json:"fingerprints"`
}

func loadBaseline(path string) (baseline, error) {
	var b baseline
	if path == "" {
		return b, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	var fp []string
	if err := json.Unmarshal(data, &fp); err == nil {
		m := make(map[string]bool, len(fp))
		for _, f := range fp {
			m[f] = true
		}
		b.Fingerprints = m
		return b, nil
	}
	// try full struct
	_ = json.Unmarshal(data, &b)
	if b.Fingerprints == nil {
		b.Fingerprints = map[string]bool{}
	}
	return b, nil
}

func filterByBaseline(findings []model.Finding, b baseline) []model.Finding {
	if len(b.Fingerprints) == 0 {
		return findings
	}
	var out []model.Finding
	for _, f := range findings {
		if f.Fingerprint != "" && b.Fingerprints[f.Fingerprint] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func writeBaseline(path string, findings []model.Finding) error {
	if path == "" {
		return nil
	}
	m := make(map[string]bool)
	for _, f := range findings {
		if f.Fingerprint != "" {
			m[f.Fingerprint] = true
		}
	}
	var arr []string
	for k := range m {
		arr = append(arr, k)
	}
	data, _ := json.MarshalIndent(arr, "", "  ")
	return os.WriteFile(path, data, 0o644)
}
