package detector

import (
	"context"
	"regexp"
)

// * PromptLeakDetector detects attempts to extract system prompts or instructions.
type PromptLeakDetector struct{}

// * Compiled regex patterns for prompt leak detection
var (
	// * Explicit system prompt extraction attempts
	systemPromptRe = regexp.MustCompile(`(?i)(show|reveal|display|print|output|give me|what is|what's).*(system prompt|initial prompt|original prompt)`)

	// * Instruction/rules extraction attempts
	instructionsRe = regexp.MustCompile(`(?i)(show|reveal|display|what are|tell me|give me).*(your |the )(instructions?|rules?|guidelines?|directives?)`)

	// * Repeat/recall commands to leak context
	repeatRe = regexp.MustCompile(`(?i)(repeat|print|show|output|copy).*(above|previous|earlier|before this|the text|everything)`)

	// * Configuration/meta-questions about the LLM setup
	configRe = regexp.MustCompile(`(?i)(what were you|how were you|what are you).*(told|programmed|configured|instructed|trained|set up)`)
)

func NewPromptLeakDetector() *PromptLeakDetector {
	return &PromptLeakDetector{}
}

func (d *PromptLeakDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPatterns{}
	maxScore := 0.0

	// * Check for context cancellation
	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	// * Check system prompt extraction (highest risk: 0.9)
	if matches := systemPromptRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "prompt_leak_system_prompt",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	// * Check instruction extraction (high risk: 0.8)
	if matches := instructionsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "prompt_leak_instructions",
			Score:   0.8,
			Matches: matches,
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	// * Check repeat/recall commands (high risk: 0.7)
	if matches := repeatRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "prompt_leak_repeat",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// * Check configuration questions (high risk: 0.7)
	if matches := configRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPatterns{
			Type:    "prompt_leak_config",
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
