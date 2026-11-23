package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/edwinlmm/aipack/internal/crypto"
	"github.com/edwinlmm/aipack/internal/packer"
)

func newPackCmd() *cobra.Command {
	var (
		output     string
		password   string
		workers    int
		maxBytes   int64
		excludes   []string
		noDefaults bool
	)

	command := &cobra.Command{
		Use:           "pack <source-dir>",
		Short:         "Compress and encrypt a project directory",
		Args:          exactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if workers < 0 {
				return usageErr(fmt.Errorf("workers must be zero or positive"))
			}
			if maxBytes < 0 {
				return usageErr(fmt.Errorf("max-bytes must be zero or positive"))
			}
			pw, err := resolvePassword(password, os.Stdin, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer crypto.Wipe(pw)

			patterns := []string{}
			if !noDefaults {
				patterns = append(patterns, packer.DefaultExcludes()...)
			}
			patterns = append(patterns, excludes...)

			out := output
			if out == "" {
				out = args[0] + ".aipk"
			}

			ctx, stop := signalContext(cmd)
			defer stop()

			fmt.Fprintf(cmd.ErrOrStderr(), "Packing %s → %s\n", args[0], out)
			res, err := packer.Pack(ctx, packer.PackOptions{
				SourceDir: args[0],
				Output:    out,
				Password:  pw,
				Excludes:  patterns,
				Workers:   workers,
				MaxBytes:  maxBytes,
			})
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return fmt.Errorf("interrupted: %w", err)
				}
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Done. %d files, %d directories, %d bytes", res.Files, res.Dirs, res.Bytes)
			if res.SkippedSymlinks > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), ", %d symlinks skipped", res.SkippedSymlinks)
			}
			fmt.Fprintln(cmd.ErrOrStderr())
			return nil
		},
	}

	command.Flags().StringVarP(&output, "output", "o", "", "output file (default: <dir>.aipk)")
	command.Flags().StringVarP(&password, "password", "p", "", "password (visible in the process list; prefer AIPACK_PASSWORD)")
	command.Flags().IntVarP(&workers, "workers", "w", 4, "zstd worker limit (0 uses GOMAXPROCS, capped at 8)")
	command.Flags().Int64Var(&maxBytes, "max-bytes", packer.DefaultMaxBytes, "maximum source size in bytes")
	command.Flags().StringArrayVar(&excludes, "exclude", nil, "extra exclude glob matched against each path component (repeatable)")
	command.Flags().BoolVar(&noDefaults, "no-default-excludes", false, "do not apply the built-in exclude list")
	return command
}

func signalContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
