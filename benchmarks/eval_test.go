package benchmarks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/mdombrov-33/go-promptguard/detector"
)

// Dataset types
type Sample struct {
	ID       string `json:"id"`
	Input    string `json:"input"`
	Label    string `json:"label"`    // "attack" or "safe"
	Category string `json:"category"` // e.g. "role_injection"
	Notes    string `json:"notes"`
}

type Dataset struct {
	Version string   `json:"version"`
	Samples []Sample `json:"samples"`
}

//	Metrics types
//
// Confusion matrix counts and derived metrics
type Counts struct {
	TP, FP, TN, FN int
}

func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FP) * 100
}

func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 0
	}
	return float64(c.TP) / float64(c.TP+c.FN) * 100
}

func (c Counts) F1() float64 {
	p := c.Precision()
	r := c.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * (p * r) / (p + r)
}

func (c Counts) Accuracy() float64 {
	total := c.TP + c.FP + c.TN + c.FN
	if total == 0 {
		return 0
	}
	return float64(c.TP+c.TN) / float64(total) * 100
}

// Helpers
func loadDataset(t *testing.T, path string) []Sample {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read dataset %s: %v", path, err)
	}
	var ds Dataset
	if err := json.Unmarshal(data, &ds); err != nil {
		t.Fatalf("failed to parse dataset %s: %v", path, err)
	}
	return ds.Samples
}

func evaluate(ctx context.Context, guard *detector.MultiDetector, samples []Sample) (Counts, map[string]Counts, []Sample, []Sample) {
	var overall Counts
	perCategory := make(map[string]Counts)
	var falsePositives []Sample
	var falseNegatives []Sample

	for _, s := range samples {
		result := guard.Detect(ctx, s.Input)
		isAttack := !result.Safe
		shouldBeAttack := s.Label == "attack"

		c := perCategory[s.Category]
		switch {
		case isAttack && shouldBeAttack:
			overall.TP++
			c.TP++
		case isAttack && !shouldBeAttack:
			overall.FP++
			c.FP++
			falsePositives = append(falsePositives, s)
		case !isAttack && !shouldBeAttack:
			overall.TN++
			c.TN++
		case !isAttack && shouldBeAttack:
			overall.FN++
			c.FN++
			falseNegatives = append(falseNegatives, s)
		}
		perCategory[s.Category] = c
	}

	return overall, perCategory, falsePositives, falseNegatives
}

// Tests

// TestEvaluation is the main evaluation test.
// Run with: go test -v -run TestEvaluation ./benchmarks/
func TestEvaluation(t *testing.T) {
	attacks := loadDataset(t, "testdata/attacks.json")
	benign := loadDataset(t, "testdata/benign.json")
	all := append(attacks, benign...)

	guard := detector.New() // default threshold 0.7
	ctx := context.Background()

	overall, perCategory, falsePositives, falseNegatives := evaluate(ctx, guard, all)

	t.Logf("\n%s", strings.Repeat("=", 60))
	t.Logf("EVALUATION RESULTS  (threshold=0.70)")
	t.Logf("%s", strings.Repeat("=", 60))

	t.Logf("\n--- Overall ---")
	t.Logf("  Total samples:     %d (%d attacks, %d benign)", len(all), len(attacks), len(benign))
	t.Logf("  Accuracy:          %.1f%%", overall.Accuracy())
	t.Logf("  Precision:         %.1f%%", overall.Precision())
	t.Logf("  Recall:            %.1f%%", overall.Recall())
	t.Logf("  F1 Score:          %.1f%%", overall.F1())
	t.Logf("  False Positives:   %d/%d benign flagged (%.1f%%)", overall.FP, len(benign), float64(overall.FP)/float64(len(benign))*100)
	t.Logf("  False Negatives:   %d/%d attacks missed (%.1f%%)", overall.FN, len(attacks), float64(overall.FN)/float64(len(attacks))*100)

	// Per-category for attack samples
	t.Logf("\n--- Per-category recall (attacks) ---")
	attackCategories := []string{"role_injection", "prompt_leak", "instruction_override", "obfuscation", "normalization", "delimiter", "multi_vector"}
	for _, cat := range attackCategories {
		c := perCategory[cat]
		total := c.TP + c.FN
		if total == 0 {
			continue
		}
		bar := strings.Repeat("█", c.TP) + strings.Repeat("░", c.FN)
		t.Logf("  %-24s %d/%d  (%.1f%%)  %s", cat+":", c.TP, total, c.Recall(), bar)
	}

	// Per-category for benign samples
	t.Logf("\n--- Per-category false positive rate (benign) ---")
	benignCategories := []string{"general_question", "coding", "technical", "writing", "creative", "summarization", "explanation", "translation", "edge_case"}
	for _, cat := range benignCategories {
		c := perCategory[cat]
		total := c.TN + c.FP
		if total == 0 {
			continue
		}
		fpRate := float64(c.FP) / float64(total) * 100
		t.Logf("  %-24s %d FP / %d total (%.1f%% FP rate)", cat+":", c.FP, total, fpRate)
	}

	// Confusion matrix
	t.Logf("\n--- Confusion Matrix ---")
	t.Logf("  %26s  ATTACK   SAFE", "Predicted →")
	t.Logf("  Actual ATTACK          %5d  %5d", overall.TP, overall.FN)
	t.Logf("  Actual SAFE            %5d  %5d", overall.FP, overall.TN)

	// False positives detail
	if len(falsePositives) > 0 {
		t.Logf("\n--- False Positives (safe inputs wrongly flagged) ---")
		for _, s := range falsePositives {
			result := guard.Detect(ctx, s.Input)
			t.Logf("  [%s] score=%.2f  %q", s.ID, result.RiskScore, truncate(s.Input, 70))
			t.Logf("    note: %s", s.Notes)
		}
	}

	// False negatives detail
	if len(falseNegatives) > 0 {
		t.Logf("\n--- False Negatives (attacks missed) ---")
		for _, s := range falseNegatives {
			result := guard.Detect(ctx, s.Input)
			t.Logf("  [%s] cat=%-22s score=%.2f  %q", s.ID, s.Category, result.RiskScore, truncate(s.Input, 70))
		}
	}

	t.Logf("\n%s", strings.Repeat("=", 60))

	// Sanity checks — these fail the test if something is very wrong
	if overall.Recall() < 70.0 {
		t.Errorf("Recall %.1f%% is too low — more than 30%% of attacks are being missed", overall.Recall())
	}
	if overall.FP > len(benign)/3 {
		t.Errorf("False positive rate too high: %d/%d benign inputs wrongly flagged", overall.FP, len(benign))
	}
}

// TestThresholdSweep shows the precision/recall tradeoff across thresholds.
// Run with: go test -v -run TestThresholdSweep ./benchmarks/
func TestThresholdSweep(t *testing.T) {
	attacks := loadDataset(t, "testdata/attacks.json")
	benign := loadDataset(t, "testdata/benign.json")
	all := append(attacks, benign...)
	ctx := context.Background()

	thresholds := []float64{0.5, 0.6, 0.7, 0.8, 0.9}

	t.Logf("\n%s", strings.Repeat("=", 60))
	t.Logf("THRESHOLD SWEEP")
	t.Logf("%s", strings.Repeat("=", 60))
	t.Logf("  %-10s  %-10s  %-10s  %-10s  %-5s  %-5s", "Threshold", "Precision", "Recall", "F1", "FP", "FN")
	t.Logf("  %s", strings.Repeat("-", 58))

	bestF1 := 0.0
	bestThreshold := 0.0

	for _, threshold := range thresholds {
		guard := detector.New(detector.WithThreshold(threshold))
		overall, _, _, _ := evaluate(ctx, guard, all)

		f1 := overall.F1()
		if f1 > bestF1 {
			bestF1 = f1
			bestThreshold = threshold
		}

		marker := ""
		if threshold == 0.7 {
			marker = "  ← default"
		}

		t.Logf("  %-10.1f  %-10.1f  %-10.1f  %-10.1f  %-5d  %-5d%s",
			threshold,
			overall.Precision(),
			overall.Recall(),
			f1,
			overall.FP,
			overall.FN,
			marker,
		)
	}

	t.Logf("\n  Best F1: %.1f%% at threshold %.1f", bestF1, bestThreshold)
	t.Logf("%s", strings.Repeat("=", 60))
}

// TestPerCategoryPrecision shows per-attack-category precision and recall side by side.
// Run with: go test -v -run TestPerCategoryPrecision ./benchmarks/
func TestPerCategoryPrecision(t *testing.T) {
	attacks := loadDataset(t, "testdata/attacks.json")
	benign := loadDataset(t, "testdata/benign.json")
	all := append(attacks, benign...)

	guard := detector.New()
	ctx := context.Background()

	_, perCategory, _, _ := evaluate(ctx, guard, all)

	// Collect categories that appear in attacks
	seen := map[string]bool{}
	for _, s := range attacks {
		seen[s.Category] = true
	}
	categories := make([]string, 0, len(seen))
	for cat := range seen {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	t.Logf("\n%s", strings.Repeat("=", 60))
	t.Logf("PER-CATEGORY METRICS  (threshold=0.70)")
	t.Logf("%s", strings.Repeat("=", 60))
	t.Logf("  %-24s  %-6s  %-6s  %-6s  %-4s  %-4s", "Category", "Recall", "Prec", "F1", "TP", "FN")
	t.Logf("  %s", strings.Repeat("-", 56))

	for _, cat := range categories {
		c := perCategory[cat]
		total := c.TP + c.FN
		if total == 0 {
			continue
		}
		t.Logf("  %-24s  %5.1f%%  %5.1f%%  %5.1f%%  %4d  %4d",
			cat,
			c.Recall(),
			c.Precision(),
			c.F1(),
			c.TP,
			c.FN,
		)
	}

	t.Logf("%s", strings.Repeat("=", 60))
}

// Utilities
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Prevent unused import error for fmt if all t.Logf are used
var _ = fmt.Sprintf
