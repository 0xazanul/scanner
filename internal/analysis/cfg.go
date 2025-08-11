package analysis

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/xab-mack/smartscanner/internal/cache"
)

// Very lightweight CFG representation: list of basic blocks with line ranges
type BasicBlock struct {
	ID      int    `json:"id"`
	StartLn int    `json:"startLine"`
	EndLn   int    `json:"endLine"`
	Label   string `json:"label"`
}

type CFG struct {
	File   string       `json:"file"`
	Blocks []BasicBlock `json:"blocks"`
	Edges  []Edge       `json:"edges"`
}

type Edge struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// BuildCFG constructs a trivial block list by splitting on function headers and return statements
func BuildCFG(filePath, content string) (*CFG, error) {
	abs, _ := filepath.Abs(filePath)
	key := cache.Key("cfg-v1", abs, content)
	if b, ok := cache.Load(key); ok {
		var cfg CFG
		if err := json.Unmarshal(b, &cfg); err == nil {
			return &cfg, nil
		}
	}
	lines := strings.Split(content, "\n")
	var blocks []BasicBlock
	current := BasicBlock{ID: 1, StartLn: 1, Label: "entry"}
	id := 1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "function ") && i+1 != current.StartLn {
			current.EndLn = i
			blocks = append(blocks, current)
			id++
			current = BasicBlock{ID: id, StartLn: i + 1, Label: "fn"}
		}
		if strings.Contains(l, "return ") {
			current.EndLn = i + 1
			blocks = append(blocks, current)
			id++
			current = BasicBlock{ID: id, StartLn: i + 2, Label: "bb"}
		}
	}
	if current.StartLn <= len(lines) {
		current.EndLn = len(lines)
		blocks = append(blocks, current)
	}
	// simple sequential edges linking blocks
	var edges []Edge
	for i := 0; i+1 < len(blocks); i++ {
		edges = append(edges, Edge{From: blocks[i].ID, To: blocks[i+1].ID})
	}
	cfg := &CFG{File: abs, Blocks: blocks, Edges: edges}
	if data, err := json.Marshal(cfg); err == nil {
		_ = cache.Store(key, data)
	}
	return cfg, nil
}
