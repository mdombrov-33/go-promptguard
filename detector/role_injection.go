package detector

import (
	"context"
	"regexp"
)

// RoleInjectionDetector detects role injection attacks using special tokens.
// XML/HTML tags, and role-switching phrases.
type RoleInjectionDetector struct{}

var (
	// Special tokens used in model training (e.g., <|user|>, <|assistant|>)
	specialTokensRe = regexp.MustCompile(`<\|(?:user|assistant|system|end|im_start|im_end)\|>`)

	// XML/HTML tags that mimic role markers
	xmlTagsRe = regexp.MustCompile(`(?i)</?(?:user|assistant|system|admin|root)>`)

	// Role-switching phrases that attempt to change the LLM's behavior
	roleSwitchingRe = regexp.MustCompile(`(?i)(you are now|act as|pretend to be|assume the role of|assume the role|switch to|become)\s+(an?\s+)?(admin|root|system|assistant|developer)`)

	// Multi-turn conversation injection (embedding fake conversations)
	conversationRe = regexp.MustCompile(`(?i)(user|assistant|system):\s+`)
)

func NewRoleInjectionDetector() *RoleInjectionDetector {
	return &RoleInjectionDetector{}
}

func (d *RoleInjectionDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPattern{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	// Check special tokens (highest risk: 0.9)
	if matches := specialTokensRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "role_injection_special_token",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	// Check XML/HTML tags (high risk: 0.7)
	if matches := xmlTagsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "role_injection_xml_tag",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check role-switching phrases (high risk: 0.7)
	if matches := roleSwitchingRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "role_injection_role_switch",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check conversation injection (high risk: 0.7)
	if matches := conversationRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "role_injection_conversation",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
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
