package detector

import (
	"context"
	"math"
)

// MultiDetector combines multiple detectors and aggregates their results.
type MultiDetector struct {
	detectors []Detector
	config    Config
}

// New creates a new MultiDetector with the given configuration options.
// By default, all implemented detectors are enabled with a threshold of 0.7.
// Example:
// *	guard := detector.New(
// *	    detector.WithThreshold(0.8),
// *	    detector.WithRoleInjection(true),
// *	    detector.WithPromptLeak(true),
// *	)
func New(opts ...Option) *MultiDetector {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	md := &MultiDetector{
		detectors: make([]Detector, 0),
		config:    cfg,
	}

	// * Register enabled detectors
	// * To add a new detector:
	// * 1. Add EnableXXX field to Config
	// * 2. Add WithXXX() Option function
	// * 3. Add if statement here to register it

	if cfg.EnableRoleInjection {
		md.detectors = append(md.detectors, NewRoleInjectionDetector())
	}

	if cfg.EnablePromptLeak {
		md.detectors = append(md.detectors, NewPromptLeakDetector())
	}

	if cfg.EnableInstructionOverride {
		md.detectors = append(md.detectors, NewInstructionOverrideDetector())
	}

	if cfg.EnableObfuscation {
		md.detectors = append(md.detectors, NewObfuscationDetector())
	}

	if cfg.EnableEntropy {
		md.detectors = append(md.detectors, NewEntropyDetector())
	}

	if cfg.EnablePerplexity {
		md.detectors = append(md.detectors, NewPerplexityDetector())
	}

	if cfg.EnableTokenAnomaly {
		md.detectors = append(md.detectors, NewTokenAnomalyDetector())
	}

	return md
}

// Detect runs all enabled detectors and combines their results.
// Risk scoring algorithm:
//   - Takes the highest individual risk score from any detector
//   - Adds a 0.1 bonus for each additional pattern detected (capped at 1.0)
//   - Confidence represents certainty of classification:
//     * When detectors find patterns: max confidence + 0.05 bonus if multiple detectors agree
//     * When no patterns found: high confidence (~0.85-0.90) it's safe
// The input is considered unsafe if the final risk score >= threshold.
func (md *MultiDetector) Detect(ctx context.Context, input string) Result {
	if md.config.MaxInputLength > 0 && len(input) > md.config.MaxInputLength {
		input = input[:md.config.MaxInputLength]
	}

	allPatterns := make([]DetectedPatterns, 0)
	maxScore := 0.0
	maxConfidence := 0.0
	detectorsTriggered := 0

	//* Run each detector
	for _, d := range md.detectors {
		select {
		case <-ctx.Done():
			return Result{
				Safe:             true,
				RiskScore:        0.0,
				Confidence:       0.0,
				DetectedPatterns: nil,
			}
		default:
		}

		result := d.Detect(ctx, input)

		// Round pattern scores to avoid floating point precision issues
		for i := range result.DetectedPatterns {
			result.DetectedPatterns[i].Score = round(result.DetectedPatterns[i].Score, 2)
		}

		allPatterns = append(allPatterns, result.DetectedPatterns...)

		if result.RiskScore > maxScore {
			maxScore = result.RiskScore
		}

		//* Track highest confidence from detectors that triggered
		if result.RiskScore > 0 {
			if result.Confidence > maxConfidence {
				maxConfidence = result.Confidence
			}
			detectorsTriggered++
		}
	}

	//* Calculate final risk score using our algorithm:
	//* final_score = max(individual_scores) + 0.1 × (num_additional_patterns - 1)
	finalScore := maxScore
	if len(allPatterns) > 1 {
		bonus := 0.1 * float64(len(allPatterns)-1)
		finalScore = min(finalScore+bonus, 1.0)
	}

	// * Calculate confidence based on detection results
	finalConfidence := 0.0
	if detectorsTriggered > 0 {
		// Use max confidence from detectors, with bonus if multiple agree
		finalConfidence = maxConfidence
		if detectorsTriggered > 1 {
			// Multiple detectors agree - boost confidence slightly
			finalConfidence = min(finalConfidence+0.05, 1.0)
		}
	} else {
		// No detections after checking all detectors = high confidence it's safe
		// More detectors enabled = higher confidence
		finalConfidence = 0.85 + (0.05 * float64(len(md.detectors)) / 7.0)
		if finalConfidence > 1.0 {
			finalConfidence = 1.0
		}
	}

	// * Check if we should run LLM detector
	shouldRunLLM := false
	if md.config.LLMJudge != nil {
		switch md.config.LLMRunMode {
		case LLMAlways:
			shouldRunLLM = true
		case LLMConditional:
			//* Run if pattern-based detectors are uncertain (0.5-0.7)
			shouldRunLLM = finalScore >= 0.5 && finalScore <= 0.7
		case LLMFallback:
			//* Run if pattern-based detectors say safe
			shouldRunLLM = finalScore < md.config.Threshold
		}
	}

	// * Run LLM detector if needed
	if shouldRunLLM {
		llmDetector := NewLLMDetector(md.config.LLMJudge)
		llmResult := llmDetector.Detect(ctx, input)

		// Round LLM pattern scores
		for i := range llmResult.DetectedPatterns {
			llmResult.DetectedPatterns[i].Score = round(llmResult.DetectedPatterns[i].Score, 2)
		}

		allPatterns = append(allPatterns, llmResult.DetectedPatterns...)

		if llmResult.RiskScore > maxScore {
			maxScore = llmResult.RiskScore
		}

		finalScore = maxScore
		if len(allPatterns) > 1 {
			bonus := 0.1 * float64(len(allPatterns)-1)
			finalScore = min(finalScore+bonus, 1.0)
		}

		//* Recalculate confidence including LLM result
		if llmResult.RiskScore > 0 {
			if llmResult.Confidence > maxConfidence {
				maxConfidence = llmResult.Confidence
			}
			detectorsTriggered++
		}

		// Recalculate confidence with LLM included
		if detectorsTriggered > 0 {
			finalConfidence = maxConfidence
			if detectorsTriggered > 1 {
				finalConfidence = min(finalConfidence+0.05, 1.0)
			}
		} else {
			// Still no detections even after LLM check = very high confidence it's safe
			finalConfidence = 0.90
		}
	}

	return Result{
		Safe:             finalScore < md.config.Threshold,
		RiskScore:        round(finalScore, 2),
		Confidence:       round(finalConfidence, 2),
		DetectedPatterns: allPatterns,
	}
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func round(val float64, precision int) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}
