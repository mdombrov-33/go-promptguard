package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "go-promptguard",
	Short: "Prompt injection detection for LLM applications",
	Long: `go-promptguard - Detect prompt injection attacks in real-time

MODES:
  Interactive TUI  - Run without arguments for terminal interface
  Quick Check      - go-promptguard check "input text"
  Batch Process    - go-promptguard batch inputs.txt
  HTTP Server      - go-promptguard server --port 8080

Run 'go-promptguard [command] --help' for more information.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runInteractive(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("go-promptguard %s\n", version)
		if commit != "none" && commit != "" {
			fmt.Printf("commit: %s\n", commit)
		}
		if date != "unknown" && date != "" {
			fmt.Printf("built: %s\n", date)
		}
	},
}

func init() {
	// If version wasn't set via ldflags, try to get it from build info
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				version = info.Main.Version
			}
		}
	}

	rootCmd.AddCommand(versionCmd)
}

func main() {
	godotenv.Load()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
