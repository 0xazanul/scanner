package solidity

import (
	"encoding/json"
	"os/exec"
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
	cmd := exec.Command(solcPath, "--ast-compact-json", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var ast ASTCompact
	if err := json.Unmarshal(out, &ast); err != nil {
		return nil, err
	}
	return &ast, nil
}
