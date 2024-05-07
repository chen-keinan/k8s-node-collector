package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "json", "Output format. One of table|json")
	rootCmd.PersistentFlags().StringP("spec", "s", "", " spec name. example: k8s-cis")
	rootCmd.PersistentFlags().StringP("version", "v", "", "spec version. example 1.23.0")
	rootCmd.PersistentFlags().StringP("node", "n", "", "node name")
	rootCmd.PersistentFlags().StringP("kubelet-config", "", "", "kubelet config via api /api/v1/nodes/<>/proxy/configz encoded in base64")
}

var rootCmd = &cobra.Command{
	Use:   "node-collector",
	Short: "trivy-collector extract file system info",
	Long:  `A tool which provide a way to extract file info which is not accessible via pre-define commands`,
	RunE: func() func(cmd *cobra.Command, args []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		}
	}(),
}

// Execute CLI commands
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
