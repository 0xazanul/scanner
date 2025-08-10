package goanalysis

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// BuildSSA constructs an SSA program for loaded packages
func BuildSSA(pkgs []*packages.Package) (*ssa.Program, []*ssa.Package) {
	prog, ssaPkgs := ssautil.AllPackages(pkgs, 0)
	prog.Build()
	return prog, ssaPkgs
}
