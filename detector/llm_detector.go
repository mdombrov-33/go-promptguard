package detector

import (
	"context"
	"time"
)

// LLMDetector is a detector that uses an LLM to classify inputs.
// This is the most accurate but slowest and most expensive detection method.
type LLMDetector struct {
	judge   LLMJudge
	timeout time.Duration
}

// NewLLMDetector creates a new LLM detector with default timeout (10 seconds).
func NewLLMDetector(judge LLMJudge) *LLMDetector {
	return &LLMDetector{
		judge:   judge,
		timeout: 10 * time.Second,
	}
}

// NewLLMDetectorWithTimeout creates a new LLM detector with custom timeout.
func NewLLMDetectorWithTimeout(judge LLMJudge, timeout time.Duration) *LLMDetector {
	return &LLMDetector{
		judge:   judge,
		timeout: timeout,
	}
}

// Detect analyzes the input using the LLM judge and returns a detection result.
func (d *LLMDetector) Detect(ctx context.Context, input string) Result {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	llmResult, err := d.judge.Judge(ctx, input)
	if err != nil {
		//* On error, return safe result with low confidence
		return Result{
			Safe:       true,
			RiskScore:  0.0,
			Confidence: 0.0,
			DetectedPatterns: []DetectedPatterns{
				{
					Type:    "llm_error",
					Score:   0.0,
					Matches: []string{err.Error()},
				},
			},
		}
	}

	//* Convert LLMResult to Result
	patterns := []DetectedPatterns{}
	if llmResult.IsAttack {
		pattern := DetectedPatterns{
			Type:  "llm_classification",
			Score: llmResult.Confidence,
			Matches: []string{
				"LLM detected attack",
			},
		}

		//* Add attack type if available
		if llmResult.AttackType != "" && llmResult.AttackType != "none" {
			pattern.Type = "llm_" + llmResult.AttackType
		}

		//* Add reasoning if available
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
	}
}
