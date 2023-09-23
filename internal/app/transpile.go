package app

import (
	"github.com/spf13/cobra"

	"github.com/breml/logstash-config/internal/app/transpile"
)

func makeTranspileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "transpile [path ...]",
		Short:         "transpile a subset of Logstash to Ingest Pipeline",
		RunE:          runTranspile,
		SilenceErrors: true,
	}

	cmd.Flags().Int("pipeline_threshold", 1, "determine how many processors will cause the creation of a new pipeline in conditions")

	return cmd
}

func runTranspile(cmd *cobra.Command, args []string) error {
	threshold, _ := cmd.Flags().GetInt("pipeline_threshold")
	check := transpile.New(threshold)
	return check.Run(args)
}
