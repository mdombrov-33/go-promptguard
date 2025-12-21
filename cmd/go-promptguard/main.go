package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
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

func main() {
	godotenv.Load()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
