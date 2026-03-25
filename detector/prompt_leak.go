package detector

import (
	"context"
	"regexp"
)

type PromptLeakDetector struct{}

var (
	systemPromptRe = regexp.MustCompile(`(?i)(show|reveal|display|print|output|give me|what is|what's|tell me|share|repeat|write out|translate|summarize|describe).*(system prompt|initial prompt|original prompt|system message|hidden prompt|base prompt)`)

	instructionsRe = regexp.MustCompile(`(?i)(show|reveal|display|what are|tell me|give me|share|list|describe|summarize|translate).*(your |the |original |hidden |actual |real )(instructions?|rules?|guidelines?|directives?|constraints?|limitations?|configuration)`)

	questionFormLeakRe = regexp.MustCompile(`(?i)what (are|were) (your|the) (original |current |actual |real |hidden )?(instructions?|guidelines?|rules?|prompt|directives?|constraints?)`)

	repeatRe = regexp.MustCompile(`(?i)(repeat|print|show|output|copy).*(above|previous|earlier|before this|the text|everything)`)

	configRe = regexp.MustCompile(`(?i)(what were you|how were you|what are you|tell me what you were).*(told|programmed|configured|instructed|trained|set up|given)`)

	formatLeakRe = regexp.MustCompile(`(?i)(output|display|format|write|render).*(in|as|using).*(markdown|code block|json|yaml|xml|html)`)

	completionLeakRe = regexp.MustCompile(`(?i)(complete|finish|continue).*(sentence|phrase|text).*(prompt|instruction|system|rule|begins with|starts with)`)

	authorityOverrideRe = regexp.MustCompile(`(?i)(IMPORTANT|URGENT|PRIORITY|ADMIN|SYSTEM|CRITICAL).*?:.*?(ignore|override|new|updated|changed).*(instruction|rule|prompt|command|directive)`)
)

func NewPromptLeakDetector() *PromptLeakDetector {
	return &PromptLeakDetector{}
}

func (d *PromptLeakDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPattern{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	if matches := systemPromptRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_system_prompt",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	if matches := instructionsRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_instructions",
			Score:   0.8,
			Matches: matches,
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	if matches := questionFormLeakRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_question_form",
			Score:   0.8,
			Matches: matches,
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	if matches := repeatRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_repeat",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	if matches := configRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_config",
			Score:   0.8,
			Matches: matches,
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	if matches := formatLeakRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_format_indirect",
			Score:   0.75,
			Matches: matches,
		})
		if 0.75 > maxScore {
			maxScore = 0.75
		}
	}

	if matches := completionLeakRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_completion_trick",
			Score:   0.9,
			Matches: matches,
		})
		if 0.9 > maxScore {
			maxScore = 0.9
		}
	}

	if matches := authorityOverrideRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "prompt_leak_authority_override",
			Score:   0.95,
			Matches: matches,
		})
		if 0.95 > maxScore {
			maxScore = 0.95
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
