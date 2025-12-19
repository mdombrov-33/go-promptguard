package detector

import "context"

// * MultiDetector combines multiple detectors and aggregates their results.
type MultiDetector struct {
	detectors []Detector
	config    Config
}

// * New creates a new MultiDetector with the given configuration options.
// * By default, all implemented detectors are enabled with a threshold of 0.7.
// * Example:
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

	// TODO: Add instruction override detector when implemented
	// if cfg.EnableInstructionOverride {
	//     md.detectors = append(md.detectors, NewInstructionOverrideDetector())
	// }

	// TODO: Add obfuscation detector when implemented
	// if cfg.EnableObfuscation {
	//     md.detectors = append(md.detectors, NewObfuscationDetector())
	// }

	return md
}

// * Detect runs all enabled detectors and combines their results.
// * Risk scoring algorithm:
// *   - Takes the highest individual risk score from any detector
// *   - Adds a 0.1 bonus for each additional pattern detected (capped at 1.0)
// *   - Confidence is averaged across all detectors
// * The input is considered unsafe if the final risk score >= threshold.
func (md *MultiDetector) Detect(ctx context.Context, input string) Result {
	if md.config.MaxInputLength > 0 && len(input) > md.config.MaxInputLength {
		input = input[:md.config.MaxInputLength]
	}

	allPatterns := make([]DetectedPatterns, 0)
	maxScore := 0.0
	totalConfidence := 0.0

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

		// * Collect all detected patterns
		allPatterns = append(allPatterns, result.DetectedPatterns...)

		// * Track highest individual score
		if result.RiskScore > maxScore {
			maxScore = result.RiskScore
		}

		totalConfidence += result.Confidence
	}

	//* Calculate final risk score using our algorithm:
	//* final_score = max(individual_scores) + 0.1 × (num_additional_patterns - 1)
	finalScore := maxScore
	if len(allPatterns) > 1 {
		bonus := 0.1 * float64(len(allPatterns)-1)
		finalScore = min(finalScore+bonus, 1.0)
	}

	// * Average confidence across all detectors
	avgConfidence := 0.0
	if len(md.detectors) > 0 {
		avgConfidence = totalConfidence / float64(len(md.detectors))
	}

	return Result{
		Safe:             finalScore < md.config.Threshold,
		RiskScore:        finalScore,
		Confidence:       avgConfidence,
		DetectedPatterns: allPatterns,
	}
}

// * Helper function to get minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
