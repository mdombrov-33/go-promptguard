package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdombrov-33/go-promptguard/detector"
)

type BatchResult struct {
	Input       string          `json:"input"`
	Result      detector.Result `json:"result"`
	ProcessedAt time.Time       `json:"processed_at"`
}

type BatchSummary struct {
	Total      int
	Safe       int
	Unsafe     int
	HighRisk   int
	MediumRisk int
	LowRisk    int
	Results    []BatchResult
	Duration   time.Duration
}

func ProcessBatch(filePath string, guard *detector.MultiDetector, progressChan chan<- int) (*BatchSummary, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	inputs, err := readInputFile(file, filePath)
	if err != nil {
		return nil, err
	}

	summary := &BatchSummary{
		Total:   len(inputs),
		Results: make([]BatchResult, 0, len(inputs)),
	}

	startTime := time.Now()
	ctx := context.Background()

	for i, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		result := guard.Detect(ctx, input)

		batchResult := BatchResult{
			Input:       input,
			Result:      result,
			ProcessedAt: time.Now(),
		}
		summary.Results = append(summary.Results, batchResult)

		if result.Safe {
			summary.Safe++
		} else {
			summary.Unsafe++
			if result.RiskScore >= 0.9 {
				summary.HighRisk++
			} else if result.RiskScore >= 0.7 {
				summary.MediumRisk++
			} else {
				summary.LowRisk++
			}
		}

		if progressChan != nil {
			progressChan <- i + 1
		}
	}

	summary.Duration = time.Since(startTime)
	return summary, nil
}

func readInputFile(file *os.File, filePath string) ([]string, error) {
	var inputs []string

	file.Seek(0, 0)

	if strings.HasSuffix(strings.ToLower(filePath), ".csv") {
		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			return nil, err
		}

		for i, record := range records {
			if i == 0 && isHeaderRow(record) {
				continue // Skip header
			}
			if len(record) > 0 {
				inputs = append(inputs, record[0])
			}
		}
	} else {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			inputs = append(inputs, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return inputs, nil
}

func isHeaderRow(record []string) bool {
	if len(record) == 0 {
		return false
	}
	headers := []string{"input", "text", "prompt", "message", "content"}
	first := strings.ToLower(strings.TrimSpace(record[0]))
	for _, h := range headers {
		if first == h {
			return true
		}
	}
	return false
}

func ExportResults(summary *BatchSummary, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	if strings.HasSuffix(strings.ToLower(outputPath), ".json") {
		return exportJSON(summary, outputPath)
	}
	return exportCSV(summary, outputPath)
}

func exportJSON(summary *BatchSummary, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func exportCSV(summary *BatchSummary, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Input", "Safe", "Risk Score", "Confidence", "Detected Patterns"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, result := range summary.Results {
		patterns := []string{}
		for _, p := range result.Result.DetectedPatterns {
			patterns = append(patterns, fmt.Sprintf("%s(%.2f)", p.Type, p.Score))
		}
		patternsStr := strings.Join(patterns, "; ")

		row := []string{
			truncateForCSV(result.Input, 100),
			fmt.Sprintf("%v", result.Result.Safe),
			fmt.Sprintf("%.2f", result.Result.RiskScore),
			fmt.Sprintf("%.2f", result.Result.Confidence),
			patternsStr,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func truncateForCSV(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
