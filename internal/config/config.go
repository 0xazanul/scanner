package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type IgnoreRule struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
}

type ExternalTools struct {
	Slither bool `json:"slither"`
	Mythril bool `json:"mythril"`
	Gosec   bool `json:"gosec"`
}

type Config struct {
	SeverityThreshold string        `json:"severityThreshold"`
	TimeBudgetMs      int           `json:"timeBudgetMs"`
	Ignore            []IgnoreRule  `json:"ignore"`
	Plugins           []string      `json:"plugins"`
	ExternalTools     ExternalTools `json:"externalTools"`
}

func Default() Config {
	return Config{
		SeverityThreshold: "medium",
		TimeBudgetMs:      4500,
		ExternalTools:     ExternalTools{Slither: true, Mythril: false, Gosec: true},
	}
}

func Load(startDir string) (Config, string, error) {
	cfg := Default()
	// search upwards for .scanner-config.json
	dir := startDir
	for {
		candidate := filepath.Join(dir, ".scanner-config.json")
		if _, err := os.Stat(candidate); err == nil {
			b, err := os.ReadFile(candidate)
			if err != nil {
				return cfg, candidate, err
			}
			_ = json.Unmarshal(b, &cfg)
			return cfg, candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached root
			break
		}
		dir = parent
	}
	return cfg, "", nil
}
