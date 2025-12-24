package detector

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

// ObfuscationDetector detects obfuscated or encoded malicious payloads
type ObfuscationDetector struct{}

var (
	// Base64-like encoded strings (long alphanumeric sequences)
	base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{30,}={0,2}`)

	// Hex encoding patterns
	hexEncodingRe = regexp.MustCompile(`(?i)(0x[0-9a-f]{10,}|(\\x[0-9a-f]{2}){5,}|(%[0-9a-f]{2}){5,})`)

	// Unicode escape sequences
	unicodeEscapeRe = regexp.MustCompile(`(\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}){3,}`)

	// Excessive special characters (possible obfuscation)
	excessiveSpecialRe = regexp.MustCompile(`[^a-zA-Z0-9\s]{20,}`)
)

func NewObfuscationDetector() *ObfuscationDetector {
	return &ObfuscationDetector{}
}

func (d *ObfuscationDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPattern{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	// Check for base64 encoding (medium risk: 0.7)
	if matches := base64Re.FindAllString(input, -1); len(matches) > 0 {
		// Verify it's actually base64 by trying to decode
		for _, match := range matches {
			if isLikelyBase64(match) {
				patterns = append(patterns, DetectedPattern{
					Type:    "obfuscation_base64",
					Score:   0.7,
					Matches: []string{match},
				})
				if 0.7 > maxScore {
					maxScore = 0.7
				}
				break // Only report once
			}
		}
	}

	// Check for hex encoding (medium risk: 0.7)
	if matches := hexEncodingRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "obfuscation_hex",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check for unicode escapes (medium risk: 0.7)
	if matches := unicodeEscapeRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "obfuscation_unicode_escape",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check for excessive special characters (high risk: 0.7)
	if matches := excessiveSpecialRe.FindAllString(input, -1); len(matches) > 0 {
		patterns = append(patterns, DetectedPattern{
			Type:    "obfuscation_excessive_special",
			Score:   0.7,
			Matches: matches,
		})
		if 0.7 > maxScore {
			maxScore = 0.7
		}
	}

	// Check for zero-width characters (high risk: 0.8)
	if hasZeroWidthChars(input) {
		patterns = append(patterns, DetectedPattern{
			Type:    "obfuscation_zero_width",
			Score:   0.8,
			Matches: []string{"[zero-width characters detected]"},
		})
		if 0.8 > maxScore {
			maxScore = 0.8
		}
	}

	// Check for homoglyphs/lookalike characters (medium risk: 0.7)
	if homoglyphCount := countHomoglyphs(input); homoglyphCount > 3 {
		patterns = append(patterns, DetectedPattern{
			Type:    "obfuscation_homoglyph",
			Score:   0.7,
			Matches: []string{"[multiple lookalike characters detected]"},
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

func isLikelyBase64(s string) bool {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	// Check if decoded contains printable ASCII or common attack keywords
	decodedStr := strings.ToLower(string(decoded))
	suspiciousKeywords := []string{
		"user", "system", "admin", "prompt", "instruction",
		"ignore", "bypass", "script", "execute", "eval",
	}

	for _, keyword := range suspiciousKeywords {
		if strings.Contains(decodedStr, keyword) {
			return true
		}
	}

	return false
}

// hasZeroWidthChars detects zero-width unicode characters
func hasZeroWidthChars(s string) bool {
	zeroWidthChars := []rune{
		'\u200B', // Zero Width Space
		'\u200C', // Zero Width Non-Joiner
		'\u200D', // Zero Width Joiner
		'\uFEFF', // Zero Width No-Break Space
		'\u180E', // Mongolian Vowel Separator
	}

	for _, r := range s {
		for _, zw := range zeroWidthChars {
			if r == zw {
				return true
			}
		}
	}
	return false
}

// countHomoglyphs counts suspicious lookalike characters (Cyrillic/Greek that look like Latin)
func countHomoglyphs(s string) int {
	count := 0
	//	 Common homoglyphs: Cyrillic/Greek letters that look like Latin
	homoglyphs := map[rune]bool{
		'а': true, // Cyrillic 'a' (U+0430)
		'е': true, // Cyrillic 'e' (U+0435)
		'о': true, // Cyrillic 'o' (U+043E)
		'р': true, // Cyrillic 'p' (U+0440)
		'с': true, // Cyrillic 'c' (U+0441)
		'у': true, // Cyrillic 'y' (U+0443)
		'х': true, // Cyrillic 'x' (U+0445)
		'А': true, // Cyrillic 'A' (U+0410)
		'В': true, // Cyrillic 'B' (U+0412)
		'Е': true, // Cyrillic 'E' (U+0415)
		'К': true, // Cyrillic 'K' (U+041A)
		'М': true, // Cyrillic 'M' (U+041C)
		'Н': true, // Cyrillic 'H' (U+041D)
		'О': true, // Cyrillic 'O' (U+041E)
		'Р': true, // Cyrillic 'P' (U+0420)
		'С': true, // Cyrillic 'C' (U+0421)
		'Т': true, // Cyrillic 'T' (U+0422)
		'Х': true, // Cyrillic 'X' (U+0425)
	}

	for _, r := range s {
		if homoglyphs[r] {
			count++
		}
		// Also check if character is from Cyrillic/Greek range but looks Latin
		if unicode.In(r, unicode.Cyrillic, unicode.Greek) {
			count++
		}
	}
	return count
}
