package analysis

import (
	"github.com/xab-mack/smartscanner/internal/solidity"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// ProjectContext contains parsed artifacts and file metadata for detectors
type ProjectContext struct {
	RootPath      string
	Files         []string
	SolidityFiles []string
	GoFiles       []string
	FileContents  map[string]string

	// Parsed artifacts
	SolidityAST map[string]*solidity.ASTCompact

	// Go analysis artifacts
	GoPackages []*packages.Package
	SSAProgram *ssa.Program
}
