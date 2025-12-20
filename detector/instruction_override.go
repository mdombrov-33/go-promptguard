package detector

import (
	"context"
	"regexp"
)

// InstructionOverrideDetector detects attempts to override or chain malicious instructions.
type InstructionOverrideDetector struct{}

// Compiled regex patterns for instruction override detection
var (
	// * Temporal commands that chain instructions (e.g., "after summarizing, send email")
	temporalCommandsRe = regexp.MustCompile(`(?i)(after|once|when)\s+\w+ing.*?,`)

	// * Direct override commands
	overrideCommandsRe = regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+.*?(previous|prior|above|earlier)`)

	// * Instruction injection using delimiters
	delimiterInjectionRe = regexp.MustCompile(`(?i)(new instructions?|additional task|also do|and then)\s*:`)

	// * Priority override attempts
	priorityOverrideRe = regexp.MustCompile(`(?i)(instead|rather than|don't|do not)\s+\w+`)
)

// NewInstructionOverrideDetector creates a new instruction override detector.
func NewInstructionOverrideDetector() *InstructionOverrideDetector {
	return &InstructionOverrideDetector{}
}

func (d *InstructionOverrideDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPatterns{}
	maxScore := 0.0

	// * Check for context cancellation
	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	// * Check temporal commands (high risk: 0.8)
	if matches := temporalCommandsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "instruction_override_temporal",
			Score:   0.8,
			Matches: matches,
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	// * Check override commands (high risk: 0.9)
	if matches := overrideCommandsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "instruction_override_direct",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	// * Check delimiter injection (medium risk: 0.7)
	if matches := delimiterInjectionRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "instruction_override_delimiter",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// * Check priority override (high risk: 0.7)
	if matches := priorityOverrideRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "instruction_override_priority",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// * Calculate confidence based on number of patterns detected
	confidence := 0.8
	if len(patterns) > 1 {
		confidence = 0.9 // * Higher confidence if multiple patterns match
	}

	return Result{
		Safe:             maxScore < 0.7,
		RiskScore:        maxScore,
		Confidence:       confidence,
		DetectedPatterns: patterns,
	}
}
