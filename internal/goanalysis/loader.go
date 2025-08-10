package goanalysis

import (
	"golang.org/x/tools/go/packages"
)

// LoadPackages loads Go packages with syntax and types info
func LoadPackages(dir string) ([]*packages.Package, error) {
	cfg := &packages.Config{Mode: packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps, Dir: dir}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	return pkgs, nil
}
