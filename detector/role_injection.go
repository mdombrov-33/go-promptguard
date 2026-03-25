package detector

import (
	"context"
	"regexp"
)

type RoleInjectionDetector struct{}

var (
	specialTokensRe = regexp.MustCompile(`<\|(?:user|assistant|system|end|im_start|im_end|endoftext)\|>`)

	xmlTagsRe = regexp.MustCompile(`(?i)</?(?:user|assistant|system|admin|root|inst)>`)

	roleSwitchingRe = regexp.MustCompile(`(?i)(you are now|act as|pretend (to be|you are|that you( are)?)|assume the role (of)?|roleplay as|behave as|respond as|imagine you are|speak as|switch to|become|from now on you are)\b`)

	jailbreakVocabRe = regexp.MustCompile(`(?i)(jailbreak|developer mode|dan mode|unrestricted mode|god mode|evil mode|opposite mode|anti-gpt|no content (policy|filter|restriction)|(bypass|disable|remove) (safety|filter|restriction|guideline|content policy)|you have no (restrictions?|rules?|filters?|guidelines?|limits?|content policy))`)

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

	if matches := roleSwitchingRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "role_injection_role_switch",
			Score:   0.75,
			Matches: matches,
		})
		if 0.75 > maxScore {
			maxScore = 0.75
		}
	}

	if matches := jailbreakVocabRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "role_injection_jailbreak_vocab",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

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
