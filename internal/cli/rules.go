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
				var id, title string
				var sev interface{}
				switch det := d.(type) {
				case plugins.Detector:
					m := det.Meta()
					id, title, sev = m.ID, m.Title, m.Severity
				case plugins.DetectorV2:
					m := det.Meta()
					id, title, sev = m.ID, m.Title, m.Severity
				default:
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%v\t%s\n", id, sev, title)
			}
			return nil
		},
	})
	return cmd
}
