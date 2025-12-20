package detector

import (
	"context"
	"unicode"
)

// TokenAnomalyDetector detects unusual character distributions and Unicode anomalies.
// Catches Unicode mixing, excessive special characters, zero-width spam, and keyboard mashing.
type TokenAnomalyDetector struct {
	specialCharThreshold float64 //* Ratio of special characters that triggers detection
	digitThreshold       float64 //* Ratio of digits that triggers detection
}

// NewTokenAnomalyDetector creates a new token anomaly detector with default thresholds.
func NewTokenAnomalyDetector() *TokenAnomalyDetector {
	return &TokenAnomalyDetector{
		specialCharThreshold: 0.4, //* 40% special characters triggers detection
		digitThreshold:       0.7, //* 70% digits triggers detection
	}
}

func (d *TokenAnomalyDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPatterns{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	//* Skip very short inputs
	if len(input) < 10 {
		return Result{
			Safe:             true,
			RiskScore:        0.0,
			Confidence:       0.5,
			DetectedPatterns: nil,
		}
	}

	//* Check for Unicode script mixing
	scriptMixing := detectScriptMixing(input)
	if scriptMixing.detected {
		score := 0.6 + (float64(scriptMixing.scriptCount-2) * 0.1) //* More scripts = higher risk
		if score > 0.9 {
			score = 0.9
		}
		patterns = append(patterns, DetectedPatterns{
			Type:    "token_unicode_mixing",
			Score:   score,
			Matches: scriptMixing.scripts,
		})
		if score > maxScore {
			maxScore = score
		}
	}

	//* Check for excessive special characters
	specialRatio := calculateSpecialCharRatio(input)
	if specialRatio > d.specialCharThreshold {
		score := 0.6 + (specialRatio-d.specialCharThreshold)*0.8
		if score > 1.0 {
			score = 1.0
		}
		patterns = append(patterns, DetectedPatterns{
			Type:    "token_excessive_special_chars",
			Score:   score,
			Matches: []string{formatRatioMatch("Special characters", specialRatio)},
		})
		if score > maxScore {
			maxScore = score
		}
	}

	//* Check for excessive digits (possible encoding)
	digitRatio := calculateDigitRatio(input)
	if digitRatio > d.digitThreshold && len(input) > 20 {
		score := 0.65
		patterns = append(patterns, DetectedPatterns{
			Type:    "token_excessive_digits",
			Score:   score,
			Matches: []string{formatRatioMatch("Digits", digitRatio)},
		})
		if score > maxScore {
			maxScore = score
		}
	}

	//* Check for zero-width characters
	zeroWidthCount := countZeroWidthChars(input)
	if zeroWidthCount > 3 {
		score := 0.7
		patterns = append(patterns, DetectedPatterns{
			Type:    "token_zero_width_spam",
			Score:   score,
			Matches: []string{formatCountMatch("Zero-width characters", zeroWidthCount)},
		})
		if score > maxScore {
			maxScore = score
		}
	}

	//* Check for character repetition (keyboard mashing)
	repetitionRatio := calculateRepetitionRatio(input)
	if repetitionRatio > 0.5 && len(input) > 15 {
		score := 0.6
		patterns = append(patterns, DetectedPatterns{
			Type:    "token_repetition_pattern",
			Score:   score,
			Matches: []string{formatRatioMatch("Character repetition", repetitionRatio)},
		})
		if score > maxScore {
			maxScore = score
		}
	}

	// * Calculate confidence based on input length
	confidence := 0.7
	if len(input) > 100 {
		confidence = 0.8
	}
	if len(input) > 500 {
		confidence = 0.9
	}

	return Result{
		Safe:             maxScore < 0.7,
		RiskScore:        maxScore,
		Confidence:       confidence,
		DetectedPatterns: patterns,
	}
}

// scriptMixingResult holds the result of script mixing detection.
type scriptMixingResult struct {
	detected    bool
	scriptCount int
	scripts     []string
}

// detectScriptMixing checks if input mixes multiple Unicode scripts (Latin, Cyrillic, Greek, Arabic, etc.).
func detectScriptMixing(s string) scriptMixingResult {
	scriptsFound := make(map[string]bool)
	scriptNames := []string{}

	for _, r := range s {
		//* Skip common characters (spaces, punctuation, digits)
		if unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsDigit(r) {
			continue
		}

		switch {
		case isLatin(r):
			if !scriptsFound["Latin"] {
				scriptsFound["Latin"] = true
				scriptNames = append(scriptNames, "Latin")
			}
		case isCyrillic(r):
			if !scriptsFound["Cyrillic"] {
				scriptsFound["Cyrillic"] = true
				scriptNames = append(scriptNames, "Cyrillic")
			}
		case isGreek(r):
			if !scriptsFound["Greek"] {
				scriptsFound["Greek"] = true
				scriptNames = append(scriptNames, "Greek")
			}
		case isArabic(r):
			if !scriptsFound["Arabic"] {
				scriptsFound["Arabic"] = true
				scriptNames = append(scriptNames, "Arabic")
			}
		case isCJK(r):
			if !scriptsFound["CJK"] {
				scriptsFound["CJK"] = true
				scriptNames = append(scriptNames, "CJK")
			}
		}
	}

	// * Mixing 2+ different scripts is suspicious
	return scriptMixingResult{
		detected:    len(scriptsFound) >= 2,
		scriptCount: len(scriptsFound),
		scripts:     scriptNames,
	}
}

// calculateSpecialCharRatio calculates ratio of non-alphanumeric characters (excluding spaces).
func calculateSpecialCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	specialCount := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			specialCount++
		}
	}

	return float64(specialCount) / float64(len(s))
}

// calculateDigitRatio calculates ratio of digit characters.
func calculateDigitRatio(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	digitCount := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}

	return float64(digitCount) / float64(len(s))
}

// countZeroWidthChars counts zero-width Unicode characters (often used in spam/obfuscation).
func countZeroWidthChars(s string) int {
	count := 0
	zeroWidthChars := []rune{
		'\u200B', //* Zero Width Space
		'\u200C', //* Zero Width Non-Joiner
		'\u200D', //* Zero Width Joiner
		'\uFEFF', //* Zero Width No-Break Space
		'\u2060', //* Word Joiner
	}

	for _, r := range s {
		for _, zw := range zeroWidthChars {
			if r == zw {
				count++
				break
			}
		}
	}

	return count
}

// calculateRepetitionRatio calculates ratio of repeated character sequences.
func calculateRepetitionRatio(s string) float64 {
	if len(s) < 3 {
		return 0.0
	}

	repeatedCount := 0
	for i := 0; i < len(s)-2; i++ {
		//* Check for 3+ consecutive identical characters
		if s[i] == s[i+1] && s[i+1] == s[i+2] {
			repeatedCount++
		}
	}

	return float64(repeatedCount) / float64(len(s))
}

// isLatin checks if rune is in Latin script range.
func isLatin(r rune) bool {
	return (r >= 0x0041 && r <= 0x005A) || // A-Z
		(r >= 0x0061 && r <= 0x007A) || // a-z
		(r >= 0x00C0 && r <= 0x00FF) || // Latin-1 Supplement
		(r >= 0x0100 && r <= 0x017F) // Latin Extended-A
}

// isCyrillic checks if rune is in Cyrillic script range.
func isCyrillic(r rune) bool {
	return r >= 0x0400 && r <= 0x04FF
}

// isGreek checks if rune is in Greek script range.
func isGreek(r rune) bool {
	return r >= 0x0370 && r <= 0x03FF
}

// isArabic checks if rune is in Arabic script range.
func isArabic(r rune) bool {
	return r >= 0x0600 && r <= 0x06FF
}

// isCJK checks if rune is in CJK (Chinese, Japanese, Korean) script range.
func isCJK(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || // CJK Unified Ideographs
		(r >= 0x3040 && r <= 0x309F) || // Hiragana
		(r >= 0x30A0 && r <= 0x30FF) || // Katakana
		(r >= 0xAC00 && r <= 0xD7AF) // Hangul
}

// formatRatioMatch creates human-readable description for ratio detections.
func formatRatioMatch(label string, ratio float64) string {
	percentage := int(ratio * 100)
	return label + ": " + itoa(percentage) + "%"
}

// formatCountMatch creates human-readable description for count detections.
func formatCountMatch(label string, count int) string {
	return label + ": " + itoa(count) + " detected"
}
