// Package cmd is the aipack command line.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Execute runs the CLI and exits with a Unix status code.
func Execute() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, err)
	var usage *usageError
	if errors.As(err, &usage) {
		return 2
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	return 1
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "aipack",
		Short: "Pack programming projects with extreme compression and encryption",
		Long: `aipack compresses a project directory with zstd and encrypts it with
AES-256-GCM. The key is derived from a password with Argon2id.

The archive can be transferred without revealing its contents, then unpacked
and fed to an AI tool.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return usageErr(err)
	})
	root.AddCommand(newPackCmd())
	root.AddCommand(newUnpackCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newCompletionCmd())
	return root
}

// version is overridden with -ldflags "-X github.com/edwinlmm/aipack/cmd.version=..."
var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "version",
		Short:         "Print the build version",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version)
			return nil
		},
	}
}

type usageError struct {
	err error
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageErr(err error) error {
	return &usageError{err: err}
}

func exactArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return usageErr(fmt.Errorf("%s accepts %d arg(s), received %d", cmd.CommandPath(), n, len(args)))
		}
		return nil
	}
}
