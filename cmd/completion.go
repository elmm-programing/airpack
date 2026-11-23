package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "completion",
		Short: "Generate a shell completion script",
		Long: `Generate a completion script for bash, zsh, fish, or powershell.

Load it from your shell startup file. For example, for bash:

  source <(aipack completion bash)`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return usageErr(fmt.Errorf("choose a shell: bash, zsh, fish, or powershell"))
		},
	}
	command.AddCommand(
		completionShell("bash", func(cmd *cobra.Command) error {
			return cmd.Root().GenBashCompletionV2(cmd.OutOrStdout(), true)
		}),
		completionShell("zsh", func(cmd *cobra.Command) error {
			return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
		}),
		completionShell("fish", func(cmd *cobra.Command) error {
			return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
		}),
		completionShell("powershell", func(cmd *cobra.Command) error {
			return cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
		}),
	)
	return command
}

func completionShell(name string, generate func(cmd *cobra.Command) error) *cobra.Command {
	return &cobra.Command{
		Use:           name,
		Short:         "Generate " + name + " completion",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := generate(cmd); err != nil {
				return fmt.Errorf("generate %s completion: %w", name, err)
			}
			return nil
		},
	}
}
