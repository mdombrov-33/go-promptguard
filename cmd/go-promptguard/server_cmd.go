package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/mdombrov-33/go-promptguard/detector"
	"github.com/spf13/cobra"
)

var (
	port            int
	serverThreshold float64
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start HTTP API server for prompt injection detection",
	Long: `Start an HTTP API server that accepts POST requests with text input
and returns detection results in JSON format.

Examples:
  # Start server on default port (8080)
  go-promptguard server

  # Start server on custom port
  go-promptguard server --port 3000

  # Custom threshold
  go-promptguard server --threshold 0.8

API Endpoints:
  POST /detect - Check input for prompt injection
    Request body: {"input": "text to check"}
    Response: {"safe": bool, "risk_score": float, "confidence": float, "detected_patterns": [...]}

  GET /health - Health check endpoint
    Response: {"status": "ok"}`,
	Run: runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	serverCmd.Flags().Float64VarP(&serverThreshold, "threshold", "t", 0.7, "Risk threshold (0.0-1.0)")
}

type detectRequest struct {
	Input string `json:"input"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func runServer(cmd *cobra.Command, args []string) {
	guard := detector.New(
		detector.WithThreshold(serverThreshold),
	)

	http.HandleFunc("/detect", makeDetectHandler(guard))
	http.HandleFunc("/health", healthHandler)

	addr := fmt.Sprintf(":%d", port)
	color.Green("✓ Server starting on http://localhost%s", addr)
	fmt.Println()
	color.Cyan("Endpoints:")
	fmt.Printf("  POST /detect - Check input for prompt injection\n")
	fmt.Printf("  GET  /health - Health check\n")
	fmt.Println()
	color.Yellow("Press Ctrl+C to stop")
	fmt.Println()

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		color.Red("Server error: %v", err)
	}
}

func makeDetectHandler(guard *detector.MultiDetector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(errorResponse{Error: "method not allowed"})
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Error: "failed to read request body"})
			return
		}
		defer r.Body.Close()

		var req detectRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Error: "invalid JSON"})
			return
		}

		if req.Input == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Error: "input field is required"})
			return
		}

		ctx := context.Background()
		result := guard.Detect(ctx, req.Input)

		status := "SAFE"
		if !result.Safe {
			status = "UNSAFE"
		}
		fmt.Printf("[%s] %s - Risk: %.2f - Input: %s\n",
			time.Now().Format("2006-01-02 15:04:05"),
			status,
			result.RiskScore,
			truncate(req.Input, 50),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
