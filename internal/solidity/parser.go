package solidity

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/xab-mack/smartscanner/internal/cache"
)

// ASTCompact represents a subset of solc --ast-compact-json output.
type ASTCompact struct {
	AbsolutePath    string           `json:"absolutePath"`
	ExportedSymbols map[string][]int `json:"exportedSymbols"`
	Nodes           []map[string]any `json:"nodes"`
}

// ParseWithSolc runs solc to obtain compact AST for a Solidity file.
func ParseWithSolc(path string, solcPath string) (*ASTCompact, error) {
	if solcPath == "" {
		solcPath = "solc"
	}
	abs, _ := filepath.Abs(path)
	// cache by file content and solc path
	b, _ := os.ReadFile(abs)
	key := cache.Key("solc-ast", solcPath, abs, string(b))
	if cached, ok := cache.Load(key); ok {
		var ast ASTCompact
		if err := json.Unmarshal(cached, &ast); err == nil {
			return &ast, nil
		}
	}
	cmd := exec.Command(solcPath, "--ast-compact-json", abs)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var ast ASTCompact
	if err := json.Unmarshal(out, &ast); err != nil {
		return nil, err
	}
	_ = cache.Store(key, out)
	return &ast, nil
}
