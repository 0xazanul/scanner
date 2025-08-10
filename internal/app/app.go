package app

import (
	"github.com/spf13/cobra"
	"github.com/xab-mack/smartscanner/internal/cli"
)

func BuildRoot() *cobra.Command {
	root := &cobra.Command{Use: "smartscanner", Short: "Next-gen smart contract vulnerability scanner"}
	cli.AddCommands(root)
	return root
}
