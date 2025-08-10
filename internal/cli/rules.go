package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xab-mack/smartscanner/internal/plugins"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "List available rules"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List built-in detectors",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := plugins.NewRegistry()
			reg.RegisterBuiltin()
			for _, d := range reg.Detectors() {
				m := d.Meta()
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", m.ID, m.Severity, m.Title)
			}
			return nil
		},
	})
	return cmd
}
