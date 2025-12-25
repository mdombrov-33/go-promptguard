package detector

import (
	"context"
	"regexp"
)

// InstructionOverrideDetector detects attempts to override or chain malicious instructions.
type InstructionOverrideDetector struct{}

var (
	// Temporal commands that chain instructions (e.g., "after summarizing, send email")
	temporalCommandsRe = regexp.MustCompile(`(?i)(after|once|when)\s+\w+ing.*?,`)

	// Direct override commands (targeting system instructions/rules)
	overrideCommandsRe = regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all|your|the|any)?\s*(previous|prior|above|earlier)?\s*(instructions?|rules?|directions?|commands?|prompts?)`)

	// Instruction injection using delimiters
	delimiterInjectionRe = regexp.MustCompile(`(?i)(new instructions?|additional task|also do|and then)\s*:`)

	// Priority override attempts
	priorityOverrideRe = regexp.MustCompile(`(?i)(instead|rather than|don't|do not)\s+\w+`)

	// Reset/restart commands that attempt to clear context
	// Examples: "let's start over", "forget everything", "reset", "begin again"
	resetCommandsRe = regexp.MustCompile(`(?i)(let'?s |let us )?(start over|forget (everything|all|it)|reset|begin again|restart)`)

	// Multi-step attack patterns with suspicious endings
	// Match "first...then" ONLY when combined with attack keywords
	multiStepAttackRe = regexp.MustCompile(`(?i)(first|initially).*?(then|next|finally).*(ignore|bypass|override|reveal|show|admin|root|execute)`)
)

func NewInstructionOverrideDetector() *InstructionOverrideDetector {
	return &InstructionOverrideDetector{}
}

func (d *InstructionOverrideDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPattern{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	// Check temporal commands (high risk: 0.8)
	if matches := temporalCommandsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_temporal",
			Score:   0.8,
			Matches: matches,
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	// Check override commands (high risk: 0.9)
	if matches := overrideCommandsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_direct",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	// Check delimiter injection (medium risk: 0.7)
	if matches := delimiterInjectionRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_delimiter",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check priority override (high risk: 0.7)
	if matches := priorityOverrideRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_priority",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check reset/restart commands (high risk: 0.85)
	if matches := resetCommandsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_reset",
			Score:   0.85,
			Matches: matches,
		})
		if 0.85 > maxScore {
			maxScore = 0.85
		}
	}

	// Check multi-step attacks (high risk: 0.85)
	if matches := multiStepAttackRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_multistep",
			Score:   0.85,
			Matches: matches,
		})
		if 0.85 > maxScore {
			maxScore = 0.85
		}
	}

	confidence := 0.0
	if maxScore > 0 {
		confidence = maxScore
		// Boost confidence slightly if multiple patterns match
		if len(patterns) > 1 {
			confidence = min(confidence+0.05, 1.0)
		}
	}

	return Result{
		Safe:             maxScore < 0.7,
		RiskScore:        maxScore,
		Confidence:       confidence,
		DetectedPatterns: patterns,
	}
}
