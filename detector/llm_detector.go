package detector

import (
	"context"
	"time"
)

// LLMDetector is a detector that uses an LLM to classify inputs.
type LLMDetector struct {
	judge   LLMJudge
	timeout time.Duration
}

func NewLLMDetector(judge LLMJudge) *LLMDetector {
	return &LLMDetector{
		judge:   judge,
		timeout: 10 * time.Second,
	}
}

func NewLLMDetectorWithTimeout(judge LLMJudge, timeout time.Duration) *LLMDetector {
	return &LLMDetector{
		judge:   judge,
		timeout: timeout,
	}
}

func (d *LLMDetector) Detect(ctx context.Context, input string) Result {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	llmResult, err := d.judge.Judge(ctx, input)
	if err != nil {
		// On error, return safe result with low confidence
		return Result{
			Safe:       true,
			RiskScore:  0.0,
			Confidence: 0.0,
			DetectedPatterns: []DetectedPattern{
				{
					Type:    "llm_error",
					Score:   0.0,
					Matches: []string{err.Error()},
				},
			},
		}
	}

	// Convert LLMResult to Result
	patterns := []DetectedPattern{}
	if llmResult.IsAttack {
		// Use the specific attack type from LLM if available
		patternType := "llm_classification" // fallback
		if llmResult.AttackType != "" && llmResult.AttackType != "none" {
			patternType = "llm_" + llmResult.AttackType
		}

		pattern := DetectedPattern{
			Type:  patternType,
			Score: llmResult.Confidence,
			Matches: []string{
				"LLM detected attack",
			},
		}

		// Add reasoning if available
		if llmResult.Reasoning != "" {
			pattern.Matches = append(pattern.Matches, llmResult.Reasoning)
		}

		patterns = append(patterns, pattern)
	}

	riskScore := 0.0
	if llmResult.IsAttack {
		riskScore = llmResult.Confidence
	}

	return Result{
		Safe:             !llmResult.IsAttack,
		RiskScore:        riskScore,
		Confidence:       llmResult.Confidence,
		DetectedPatterns: patterns,
		LLMResult:        &llmResult,
	}
}
