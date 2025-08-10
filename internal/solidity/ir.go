package solidity

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xab-mack/smartscanner/internal/cache"
)

// Lightweight IR for heuristic analysis
type FunctionIR struct {
	Name          string `json:"name"`
	Visibility    string `json:"visibility"`
	StartsAtLine  int    `json:"startsAtLine"`
	ExternalCalls []int  `json:"externalCalls"` // line numbers
	StateWrites   []int  `json:"stateWrites"`   // line numbers
}

type FileIR struct {
	File      string       `json:"file"`
	Functions []FunctionIR `json:"functions"`
}

// BuildIR builds a heuristic IR from source content. Cached by file content.
func BuildIR(filePath string, content string) (*FileIR, error) {
	abs, _ := filepath.Abs(filePath)
	key := cache.Key("sol-ir-v1", abs, content)
	if b, ok := cache.Load(key); ok {
		var ir FileIR
		if err := json.Unmarshal(b, &ir); err == nil {
			return &ir, nil
		}
	}
	// split into functions naïvely
	lines := strings.Split(content, "\n")
	var functions []FunctionIR
	reHeader := regexp.MustCompile(`(?m)^\s*function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?`)
	for i, l := range lines {
		if m := reHeader.FindStringSubmatch(l); len(m) >= 2 {
			name := m[1]
			vis := ""
			if len(m) >= 3 {
				vis = m[2]
			}
			fn := FunctionIR{Name: name, Visibility: vis, StartsAtLine: i + 1}
			// scan forward until next function header or end, collect external calls and state writes
			for j := i; j < len(lines); j++ {
				if j != i && reHeader.MatchString(lines[j]) {
					break
				}
				low := strings.ToLower(lines[j])
				if strings.Contains(low, ".call(") || strings.Contains(low, ".call{") || strings.Contains(low, ".delegatecall(") || strings.Contains(low, ".staticcall(") {
					fn.ExternalCalls = append(fn.ExternalCalls, j+1)
				}
				if regexp.MustCompile(`\b[_a-zA-Z][\w]*\s*=`).MatchString(lines[j]) {
					fn.StateWrites = append(fn.StateWrites, j+1)
				}
			}
			functions = append(functions, fn)
		}
	}
	ir := &FileIR{File: abs, Functions: functions}
	if data, err := json.Marshal(ir); err == nil {
		_ = cache.Store(key, data)
	}
	return ir, nil
}
