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
	cmd.Flags().String("log_level", "info", "determine the log_level")
	cmd.Flags().Bool("deal_with_error_locally", true, "whether we deal with errors locally, e.g., add tag on error by default")
	cmd.Flags().Bool("add_default_global_on_failure", false, "whether to add a default global on failure")
	cmd.Flags().Bool("fidelity", true, "try to keep correct if-else semantic")

	return cmd
}

func runTranspile(cmd *cobra.Command, args []string) error {
	threshold, _ := cmd.Flags().GetInt("pipeline_threshold")
	log_level, _ := cmd.Flags().GetString("log_level")
	deal_with_error_locally, _ := cmd.Flags().GetBool("deal_with_error_locally")
	add_default_global_on_failure, _ := cmd.Flags().GetBool("add_default_global_on_failure")
	fidelity, _ := cmd.Flags().GetBool("fidelity")
	check := transpile.New(threshold, log_level, deal_with_error_locally, add_default_global_on_failure, fidelity)
	return check.Run(args)
}
