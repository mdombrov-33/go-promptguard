package main

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/mdombrov-33/go-promptguard/detector"
	"github.com/spf13/cobra"
)

var (
	batchThreshold float64
	batchOutput    string
)

var batchCmd = &cobra.Command{
	Use:   "batch [input-file]",
	Short: "Process multiple inputs from a file",
	Long: `Process multiple inputs from TXT or CSV file.

Examples:
  # Process text file (one input per line)
  go-promptguard batch inputs.txt

  # Process CSV file (first column)
  go-promptguard batch inputs.csv

  # Save results to file
  go-promptguard batch inputs.txt --output results.json
  go-promptguard batch inputs.txt --output results.csv

  # Custom threshold
  go-promptguard batch inputs.txt --threshold 0.8`,
	Run: runBatch,
}

func init() {
	rootCmd.AddCommand(batchCmd)

	batchCmd.Flags().Float64VarP(&batchThreshold, "threshold", "t", 0.7, "Risk threshold (0.0-1.0)")
	batchCmd.Flags().StringVarP(&batchOutput, "output", "o", "", "Output file (JSON or CSV)")
}

func runBatch(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		color.Red("Error: no input file provided")
		fmt.Println("\nUsage: go-promptguard batch [input-file]")
		fmt.Println("   or: go-promptguard batch inputs.txt --output results.json")
		os.Exit(1)
	}

	inputFile := args[0]

	guard := detector.New(
		detector.WithThreshold(batchThreshold),
	)

	color.Cyan("📦 Processing batch file: %s", inputFile)
	fmt.Println()

	startTime := time.Now()
	summary, err := ProcessBatch(inputFile, guard, nil)
	if err != nil {
		color.Red("Error processing batch: %v", err)
		os.Exit(1)
	}
	duration := time.Since(startTime)

	fmt.Println()
	color.Green("✓ Batch processing complete")
	fmt.Println()
	fmt.Printf("  Total:    %d\n", summary.Total)
	fmt.Printf("  Safe:     %d\n", summary.Safe)
	fmt.Printf("  Unsafe:   %d\n", summary.Unsafe)
	if summary.Unsafe > 0 {
		fmt.Printf("    High:   %d\n", summary.HighRisk)
		fmt.Printf("    Medium: %d\n", summary.MediumRisk)
		fmt.Printf("    Low:    %d\n", summary.LowRisk)
	}
	fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))
	fmt.Println()

	if batchOutput != "" {
		if err := ExportResults(summary, batchOutput); err != nil {
			color.Red("Error saving results: %v", err)
			os.Exit(1)
		}
		color.Green("✓ Results saved to: %s", batchOutput)
		fmt.Println()
	}
}
