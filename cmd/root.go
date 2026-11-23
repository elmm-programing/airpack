package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aipack",
	Short: "Pack programming projects with extreme compression and encryption for secure transfer to AI tools",
	Long: `aipack compresses project directories to the limit (zstd best) and encrypts them (AES-256-GCM + Argon2id)
so you can transfer the blob over the network without revealing contents.

After transfer, unpack to feed the source into Cursor, Claude, Grok or any AI chat.

Built with production Go practices: structured concurrency, proper error wrapping, secure crypto.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(packCmd)
	rootCmd.AddCommand(unpackCmd)
}
