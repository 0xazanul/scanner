package cli

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/xab-mack/smartscanner/internal/config"
)

func newInitCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a .scanner-config.json in the target directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = "."
			}
			cfg := config.Default()
			b, _ := json.MarshalIndent(cfg, "", "  ")
			path := filepath.Join(dir, ".scanner-config.json")
			return os.WriteFile(path, b, 0o644)
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "Directory to write config file to")
	return cmd
}
