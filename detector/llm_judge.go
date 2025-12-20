package detector

import "context"

// LLMJudge is the interface for LLM-based prompt injection detection.
// Users can implement this interface to use any LLM provider.
type LLMJudge interface {
	Judge(ctx context.Context, input string) (LLMResult, error)
}

// LLMResult represents the result from an LLM-based detection.
type LLMResult struct {
	IsAttack   bool    //* true if the input is detected as an attack
	Confidence float64 //* 0.0-1.0 confidence score
	Reasoning  string  //* Optional explanation (depends on output format)
	AttackType string  //* Optional attack classification
}

// LLMRunMode determines when the LLM detector runs.
type LLMRunMode int

const (
	// * LLMAlways runs the LLM on every input (most accurate, most expensive)
	LLMAlways LLMRunMode = iota

	// * LLMConditional runs the LLM only when pattern-based detectors are uncertain (0.5-0.7 score)
	LLMConditional

	// * LLMFallback runs the LLM only when pattern-based detectors say safe (double-check negatives)
	LLMFallback
)

// LLMOutputFormat determines the expected output format from the LLM.
type LLMOutputFormat int

const (
	// * LLMSimple expects "SAFE" or "ATTACK" response (cheap, fast)
	LLMSimple LLMOutputFormat = iota

	// * LLMStructured expects JSON response with reasoning (more tokens, more info)
	LLMStructured
)
