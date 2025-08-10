package tools

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"
)

type Result struct {
	Tool     string
	Raw      []byte
	Err      error
	Duration time.Duration
}

func RunWithTimeout(ctx context.Context, tool string, args ...string) Result {
	start := time.Now()
	cmd := exec.CommandContext(ctx, tool, args...)
	out, err := cmd.Output()
	return Result{Tool: tool, Raw: out, Err: err, Duration: time.Since(start)}
}

// Normalize is a placeholder that converts known tool outputs into a unified structure
type Finding struct {
	RuleID     string  `json:"ruleId"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	File       string  `json:"file"`
	StartLine  int     `json:"startLine"`
	EndLine    int     `json:"endLine"`
	Message    string  `json:"message"`
}

func Normalize(tool string, raw []byte) ([]Finding, error) {
	switch tool {
	case "solhint":
		return normalizeSolhint(raw)
	case "slither":
		return normalizeSlither(raw)
	case "gosec":
		return normalizeGosec(raw)
	case "govulncheck":
		return normalizeGovulncheck(raw)
	case "myth":
		return normalizeMythril(raw)
	default:
		var out []Finding
		_ = json.Unmarshal(raw, &out)
		return out, nil
	}
}
