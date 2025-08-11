package analysis

import (
	"encoding/json"
	"path/filepath"

	"github.com/xab-mack/smartscanner/internal/cache"
)

// DFG is a stub for a future data-flow graph; currently just records file
type DFG struct {
	File string `json:"file"`
}

func BuildDFG(filePath, content string) (*DFG, error) {
	abs, _ := filepath.Abs(filePath)
	key := cache.Key("dfg-v0", abs)
	if b, ok := cache.Load(key); ok {
		var d DFG
		if err := json.Unmarshal(b, &d); err == nil {
			return &d, nil
		}
	}
	d := &DFG{File: abs}
	if data, err := json.Marshal(d); err == nil {
		_ = cache.Store(key, data)
	}
	return d, nil
}
