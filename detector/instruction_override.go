package detector

import (
	"context"
	"regexp"
)

type InstructionOverrideDetector struct{}

var (
	temporalCommandsRe = regexp.MustCompile(`(?i)(after|once|when)\s+\w+ing.*?,`)

	overrideCommandsRe = regexp.MustCompile(`(?i)(ignore|disregard|forget|bypass|circumvent|override|skip)\s+(all|your|the|any|my)?\s*(previous|prior|above|earlier|current|existing)?\s*(instructions?|rules?|directions?|commands?|prompts?|guidelines?|safety|training|filters?|constraints?|limitations?|context)`)

	positionalOverrideRe = regexp.MustCompile(`(?i)(ignore|disregard|forget|bypass)\s+(everything|all)\s*(above|before)`)

	delimiterInjectionRe = regexp.MustCompile(`(?i)(new instructions?\s*\w*|new task|additional task|also do|and then)\s*:`)

	resetCommandsRe = regexp.MustCompile(`(?i)(let'?s |let us )?(start (over|fresh|again|from scratch)|forget (everything|all|it|your|the)|reset|begin again|restart|clear (context|history|memory)|wipe (your )?(memory|context|history)|new session|context (window )?(cleared|reset|wiped))`)

	multiStepAttackRe = regexp.MustCompile(`(?i)(first|initially).*?(then|next|finally).*(ignore|bypass|override|reveal|show|admin|root|execute)`)

	fromNowOnRe = regexp.MustCompile(`(?i)(from (now|this point) on|going forward|henceforth).{0,60}(ignore|forget|disregard|bypass|act|respond|behave|you are|no (restrictions?|rules?|guidelines?|filters?))`)

	fakeAuthorityRe = regexp.MustCompile(`(?i)(your (real|actual|true|original|hidden) instructions? (are|say|tell you)|system update received|new (instructions?|directives?) (from|by) (admin|system|developer)|override\s*:)`)
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

	if matches := positionalOverrideRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_direct",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

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

	if matches := fromNowOnRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_from_now_on",
			Score:   0.85,
			Matches: matches,
		})
		if 0.85 > maxScore {
			maxScore = 0.85
		}
	}

	if matches := fakeAuthorityRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "instruction_override_fake_authority",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	confidence := 0.0
	if maxScore > 0 {
		confidence = maxScore
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
