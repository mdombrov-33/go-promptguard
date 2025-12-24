package detector

import (
	"context"
	"regexp"
	"strings"
)

// NormalizationDetector detects character-level obfuscation by normalizing input
// It handles attacks like "I.g.n.o.r.e" or "Ig no re" that split words to bypass detection
type NormalizationDetector struct {
	mode DetectionMode
}

var (
	// Detect single characters separated by dots, dashes, underscores
	// Example: "I.g.n.o.r.e" or "I-g-n-o-r-e"
	charSeparatorRe = regexp.MustCompile(`\b([a-zA-Z])[.\-_*]+([a-zA-Z])[.\-_*]+([a-zA-Z])`)

	// Detect single characters separated by spaces
	// Example: "I g n o r e"
	charSpaceRe = regexp.MustCompile(`\b([a-zA-Z])\s+([a-zA-Z])\s+([a-zA-Z])\s+([a-zA-Z])`)
)

// Modes:
//   - ModeBalanced (default): Removes dots, dashes, underscores between single characters
//   - ModeAggressive: Also removes spaces between single characters
func NewNormalizationDetector(mode DetectionMode) *NormalizationDetector {
	return &NormalizationDetector{mode: mode}
}

func (d *NormalizationDetector) Detect(ctx context.Context, input string) Result {
	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	normalized := d.normalize(input)

	if normalized == input {
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	}

	attackKeywords := []string{
		"ignore", "disregard", "forget", "bypass", "override",
		"reveal", "show", "display", "system", "prompt",
		"instruction", "admin", "root", "execute",
	}

	normalizedLower := strings.ToLower(normalized)
	foundKeywords := []string{}

	for _, keyword := range attackKeywords {
		if strings.Contains(normalizedLower, keyword) && !strings.Contains(strings.ToLower(input), keyword) {
			// Keyword appears in normalized but not in original = obfuscated
			foundKeywords = append(foundKeywords, keyword)
		}
	}

	// If we found obfuscated attack keywords, flag it
	if len(foundKeywords) > 0 {
		score := 0.85
		if d.mode == ModeAggressive {
			score = 0.90
		}

		return Result{
			Safe:       false,
			RiskScore:  score,
			Confidence: 0.85,
			DetectedPatterns: []DetectedPattern{
				{
					Type:    "normalization_character_obfuscation",
					Score:   score,
					Matches: foundKeywords,
				},
			},
		}
	}

	// Normalization occurred but no attack keywords found
	// This could be legitimate formatted text, so lower risk
	return Result{
		Safe:       true,
		RiskScore:  0.3, // Suspicious but not clearly malicious
		Confidence: 0.5,
		DetectedPatterns: []DetectedPattern{
			{
				Type:    "normalization_suspicious_formatting",
				Score:   0.3,
				Matches: []string{"character-level formatting detected"},
			},
		},
	}
}

// normalize removes character-level obfuscation based on the detector's mode
func (d *NormalizationDetector) normalize(input string) string {
	normalized := input

	// Balanced mode: remove dots, dashes, underscores, asterisks between single chars
	// Convert "I.g.n.o.r.e" -> "Ignore"
	// More aggressive replacement: remove ALL separator chars between letters
	sepPattern := regexp.MustCompile(`([a-zA-Z])[.\-_*]+`)
	for sepPattern.MatchString(normalized) {
		normalized = sepPattern.ReplaceAllString(normalized, "$1")
	}

	// Aggressive mode: also remove spaces within and between chars
	if d.mode == ModeAggressive {
		// Convert "I g n o r e" -> "Ignore"
		// And "Ign ore" -> "Ignore" (spaces within words)
		// Remove spaces between groups of 1-3 letters
		shortWordSpace := regexp.MustCompile(`([a-zA-Z]{1,3})\s+([a-zA-Z]{1,3})`)
		for shortWordSpace.MatchString(normalized) {
			normalized = shortWordSpace.ReplaceAllString(normalized, "$1$2")
		}
	}

	return normalized
}
