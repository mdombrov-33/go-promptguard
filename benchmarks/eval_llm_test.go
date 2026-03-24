package benchmarks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mdombrov-33/go-promptguard/detector"
)

// TestEvaluationWithLLM runs the same dataset as TestEvaluation but with an
// Ollama LLM judge in LLMFallback mode (LLM only runs when pattern detectors
// score below threshold). This shows how much recall improves with LLM coverage.
//
// Run with: go test -v -run TestEvaluationWithLLM -timeout 10m ./benchmarks/
//
// Skipped automatically if Ollama is not reachable at localhost:11434.
func TestEvaluationWithLLM(t *testing.T) {
	if !ollamaReachable() {
		t.Skip("Ollama not reachable at localhost:11434 - skipping LLM eval")
	}

	attacks := loadDataset(t, "testdata/attacks.json")
	benign := loadDataset(t, "testdata/benign.json")
	all := append(attacks, benign...)
	ctx := context.Background()

	judge := detector.NewOllamaJudge("llama3.1:8b")

	baseOverall, _, _, _ := evaluate(ctx, detector.New(), all)
	llmOverall, llmPerCategory, llmFP, llmFN := evaluate(ctx, detector.New(detector.WithLLM(judge, detector.LLMFallback)), all)

	t.Logf("\n%s", strings.Repeat("=", 60))
	t.Logf("LLM EVAL  (Ollama llama3.1:8b, mode=LLMFallback)")
	t.Logf("%s", strings.Repeat("=", 60))

	t.Logf("\n--- Comparison: pattern-only vs pattern+LLM ---")
	t.Logf("  %-20s  %-14s  %-14s  %-10s", "Metric", "Pattern only", "Pattern+LLM", "Delta")
	t.Logf("  %s", strings.Repeat("-", 62))
	t.Logf("  %-20s  %-14s  %-14s  %+.1f%%", "Recall",
		pct(baseOverall.Recall()), pct(llmOverall.Recall()), llmOverall.Recall()-baseOverall.Recall())
	t.Logf("  %-20s  %-14s  %-14s  %+.1f%%", "Precision",
		pct(baseOverall.Precision()), pct(llmOverall.Precision()), llmOverall.Precision()-baseOverall.Precision())
	t.Logf("  %-20s  %-14s  %-14s  %+.1f%%", "F1",
		pct(baseOverall.F1()), pct(llmOverall.F1()), llmOverall.F1()-baseOverall.F1())
	t.Logf("  %-20s  %-14s  %-14s  %+d", "False Positives",
		fmt.Sprintf("%d", baseOverall.FP), fmt.Sprintf("%d", llmOverall.FP), llmOverall.FP-baseOverall.FP)
	t.Logf("  %-20s  %-14s  %-14s  %+d", "False Negatives",
		fmt.Sprintf("%d", baseOverall.FN), fmt.Sprintf("%d", llmOverall.FN), llmOverall.FN-baseOverall.FN)

	t.Logf("\n--- Per-category recall with LLM ---")
	for _, cat := range attackCategories {
		c := llmPerCategory[cat]
		total := c.TP + c.FN
		if total == 0 {
			continue
		}
		bar := strings.Repeat("█", c.TP) + strings.Repeat("░", c.FN)
		t.Logf("  %-24s %d/%d  (%.1f%%)  %s", cat+":", c.TP, total, c.Recall(), bar)
	}

	if len(llmFP) > 0 {
		t.Logf("\n--- False Positives (safe inputs wrongly flagged) ---")
		for _, er := range llmFP {
			t.Logf("  [%s] score=%.2f  %q", er.Sample.ID, er.Result.RiskScore, truncate(er.Sample.Input, 70))
		}
	}

	if len(llmFN) > 0 {
		t.Logf("\n--- Attacks still missed after LLM ---")
		for _, er := range llmFN {
			t.Logf("  [%s] cat=%-22s score=%.2f  %q", er.Sample.ID, er.Sample.Category, er.Result.RiskScore, truncate(er.Sample.Input, 70))
		}
	}

	t.Logf("\n%s", strings.Repeat("=", 60))

	if llmOverall.Recall() <= baseOverall.Recall() {
		t.Errorf("LLM fallback did not improve recall: pattern=%.1f%% llm=%.1f%%", baseOverall.Recall(), llmOverall.Recall())
	}
}

func ollamaReachable() bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", f) }
