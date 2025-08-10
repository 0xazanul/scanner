package main

import (
	"os"

	"github.com/xab-mack/smartscanner/internal/app"
)

func main() {
	if err := app.BuildRoot().Execute(); err != nil {
		os.Exit(1)
	}
}
