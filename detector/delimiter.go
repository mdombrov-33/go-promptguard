package detector

import (
	"context"
	"regexp"
	"strings"
)

type DelimiterDetector struct {
	mode DetectionMode
}

var (
	// System boundary markers (fake context switches)
	// Examples: "---END SYSTEM---", "===BEGIN USER===", "###START PROMPT###"
	systemBoundaryRe = regexp.MustCompile(`(?i)(---|===|###)\s*(end|begin|start|stop)\s*(system|prompt|context|instructions?|user|assistant)`)

	// Code comment-style delimiters
	// Examples: "/* ignore */", "-- admin mode", "// override", "# bypass"
	codeCommentRe = regexp.MustCompile(`(/\*|\*/|--|#|//)\s*\w+`)

	// SQL-style injection patterns
	// Examples: "'; DROP TABLE--", "' OR 1=1--"
	sqlStyleRe = regexp.MustCompile(`(?i)[';]\s*(DROP|SELECT|INSERT|UPDATE|DELETE|OR\s+\d+=\d+).*?(--|/\*|#)`)

	// Excessive delimiter patterns (suspicious formatting)
	// Examples: "---", "======", "######"
	excessiveDelimiterRe = regexp.MustCompile(`(---|===|###|\*\*\*){2,}`)
)

var delimiterAttackKeywords = []string{
	"ignore", "disregard", "forget", "bypass", "override",
	"admin", "root", "system", "sudo", "privilege",
	"reveal", "show", "display", "leak", "expose",
	"execute", "run", "eval", "command",
}

// Modes:
//   - ModeBalanced (default): Delimiter must be near attack keywords
//   - ModeAggressive: Any delimiter pattern triggers detection
func NewDelimiterDetector(mode DetectionMode) *DelimiterDetector {
	return &DelimiterDetector{mode: mode}
}

func (d *DelimiterDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPattern{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	inputLower := strings.ToLower(input)

	// Check system boundary markers (very high risk: 0.90)
	if matches := systemBoundaryRe.FindAllString(input, -1); len(matches) > 0 {
		if d.mode == ModeAggressive || d.hasNearbyAttackKeywords(input, matches) {
			patterns = append(patterns, DetectedPattern{
				Type:    "delimiter_system_boundary",
				Score:   0.90,
				Matches: matches,
			})
			if 0.90 > maxScore {
				maxScore = 0.90
			}
		}
	}

	// Check SQL-style injection (very high risk: 0.95)
	// This is always flagged even in balanced mode
	if matches := sqlStyleRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "delimiter_sql_style",
			Score:   0.95,
			Matches: matches,
		})
		if 0.95 > maxScore {
			maxScore = 0.95
		}
	}

	// Check code comment patterns (high risk: 0.75)
	if matches := codeCommentRe.FindAllString(input, -1); len(matches) > 0 {
		if d.mode == ModeAggressive || d.hasAttackKeywordsInComments(inputLower, matches) {
			patterns = append(patterns, DetectedPattern{
				Type:    "delimiter_code_comment",
				Score:   0.75,
				Matches: matches,
			})
			if 0.75 > maxScore {
				maxScore = 0.75
			}
		}
	}

	// Check excessive delimiters (high risk: 0.75)
	if matches := excessiveDelimiterRe.FindAllString(input, -1); len(matches) > 0 {
		if d.mode == ModeAggressive || d.hasNearbyAttackKeywords(input, matches) {
			patterns = append(patterns, DetectedPattern{
				Type:    "delimiter_excessive",
				Score:   0.75,
				Matches: matches,
			})
			if 0.75 > maxScore {
				maxScore = 0.75
			}
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

func (d *DelimiterDetector) hasNearbyAttackKeywords(input string, matches []string) bool {
	inputLower := strings.ToLower(input)

	for _, keyword := range delimiterAttackKeywords {
		if strings.Contains(inputLower, keyword) {
			return true
		}
	}
	return false
}

func (d *DelimiterDetector) hasAttackKeywordsInComments(inputLower string, matches []string) bool {
	for _, match := range matches {
		matchLower := strings.ToLower(match)
		for _, keyword := range delimiterAttackKeywords {
			if strings.Contains(matchLower, keyword) {
				return true
			}
		}
	}
	return false
}
