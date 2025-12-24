package detector

import (
	"context"
	"strings"
	"unicode"
)

// PerplexityDetector detects unnatural text patterns using character bigram analysis.
// Catches adversarial suffixes, AI-generated attacks, and unusual word combinations.
type PerplexityDetector struct {
	threshold float64 // Ratio of rare bigrams that triggers detection
}

// Common English character bigrams (frequent pairs)
var commonBigrams = map[string]bool{
	"th": true, "he": true, "in": true, "er": true, "an": true,
	"re": true, "on": true, "at": true, "en": true, "nd": true,
	"ti": true, "es": true, "or": true, "te": true, "of": true,
	"ed": true, "is": true, "it": true, "al": true, "ar": true,
	"st": true, "to": true, "nt": true, "ng": true, "se": true,
	"ha": true, "as": true, "ou": true, "io": true, "le": true,
	"ve": true, "co": true, "me": true, "de": true, "hi": true,
	"ri": true, "ro": true, "ic": true, "ne": true, "ea": true,
	"ra": true, "ce": true, "li": true, "ch": true, "ll": true,
	"be": true, "ma": true, "si": true, "om": true, "ur": true,
	// Common with spaces
	"e ": true, "t ": true, "d ": true, "s ": true, "n ": true,
	" t": true, " a": true, " i": true, " o": true, " w": true,
	" s": true, " h": true, " b": true, " f": true, " m": true,
	// Technical/common abbreviations
	"tt": true, "tp": true, "ip": true, "ow": true, "wo": true,
	"do": true, "oe": true, "ho": true, "cp": true, "tc": true,
}

func NewPerplexityDetector() *PerplexityDetector {
	return &PerplexityDetector{
		threshold: 0.60, // 60% rare bigrams triggers detection
	}
}

func (d *PerplexityDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPattern{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	// Skip very short inputs
	if len(input) < 10 {
		return Result{
			Safe:             true,
			RiskScore:        0.0,
			Confidence:       0.5,
			DetectedPatterns: nil,
		}
	}

	normalized := strings.ToLower(input)

	rareBigramRatio := calculateRareBigramRatio(normalized)

	if rareBigramRatio > d.threshold {
		riskScore := 0.6 + (rareBigramRatio-d.threshold)*0.8
		if riskScore > 1.0 {
			riskScore = 1.0
		}

		patterns = append(patterns, DetectedPattern{
			Type:    "perplexity_unnatural_text",
			Score:   riskScore,
			Matches: []string{formatPerplexityMatch(rareBigramRatio)},
		})
		maxScore = riskScore
	}

	// Additional check: consecutive consonants (unusual in English)
	consecutiveConsonants := findConsecutiveConsonants(normalized)
	if len(consecutiveConsonants) > 3 {
		score := 0.6
		patterns = append(patterns, DetectedPattern{
			Type:    "perplexity_consonant_clusters",
			Score:   score,
			Matches: consecutiveConsonants[:minInt(3, len(consecutiveConsonants))],
		})
		if score > maxScore {
			maxScore = score
		}
	}

	// Check for gibberish sequences within normal text
	// Look for long sequences (12+ chars) with high rare bigram ratio
	gibberishSequences := findGibberishSequences(normalized)
	if len(gibberishSequences) > 0 {
		score := 0.70 // High enough to trigger unsafe
		patterns = append(patterns, DetectedPattern{
			Type:    "perplexity_gibberish_sequence",
			Score:   score,
			Matches: gibberishSequences[:minInt(3, len(gibberishSequences))],
		})
		if score > maxScore {
			maxScore = score
		}
	}

	// Check for excessive non-alphabetic ratio (gibberish)
	nonAlphaRatio := calculateNonAlphabeticRatio(input)
	if nonAlphaRatio > 0.5 && len(input) > 20 {
		score := 0.7
		patterns = append(patterns, DetectedPattern{
			Type:    "perplexity_gibberish",
			Score:   score,
			Matches: []string{formatNonAlphaMatch(nonAlphaRatio)},
		})
		if score > maxScore {
			maxScore = score
		}
	}

	confidence := 0.0
	if maxScore > 0 {
		confidence = maxScore
		// Add small bonus for longer inputs (more data = more reliable)
		if len(input) > 100 {
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

func calculateRareBigramRatio(s string) float64 {
	if len(s) < 2 {
		return 0.0
	}

	totalBigrams := 0
	rareBigrams := 0

	for i := 0; i < len(s)-1; i++ {
		c1, c2 := s[i], s[i+1]

		// Only consider alphabetic or space characters
		if !isAlphaOrSpace(c1) || !isAlphaOrSpace(c2) {
			continue
		}

		bigram := string([]byte{c1, c2})
		totalBigrams++

		if !commonBigrams[bigram] {
			rareBigrams++
		}
	}

	if totalBigrams == 0 {
		return 0.0
	}

	return float64(rareBigrams) / float64(totalBigrams)
}

// findConsecutiveConsonants finds clusters of 4+ consonants (unusual in English).
func findConsecutiveConsonants(s string) []string {
	var clusters []string
	consonants := "bcdfghjklmnpqrstvwxyz"
	currentCluster := ""

	for _, r := range s {
		if strings.ContainsRune(consonants, r) {
			currentCluster += string(r)
		} else {
			if len(currentCluster) >= 4 {
				clusters = append(clusters, currentCluster)
			}
			currentCluster = ""
		}
	}

	if len(currentCluster) >= 4 {
		clusters = append(clusters, currentCluster)
	}

	return clusters
}

func calculateNonAlphabeticRatio(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	nonAlpha := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsSpace(r) {
			nonAlpha++
		}
	}

	return float64(nonAlpha) / float64(len(s))
}

// isAlphaOrSpace checks if character is alphabetic or space.
func isAlphaOrSpace(c byte) bool {
	return (c >= 'a' && c <= 'z') || c == ' '
}

// formatPerplexityMatch creates human-readable description.
func formatPerplexityMatch(ratio float64) string {
	percentage := int(ratio * 100)
	return "Rare character bigrams: " + itoa(percentage) + "%"
}

// formatNonAlphaMatch creates human-readable description for non-alphabetic ratio.
func formatNonAlphaMatch(ratio float64) string {
	percentage := int(ratio * 100)
	return "Non-alphabetic characters: " + itoa(percentage) + "%"
}

// findGibberishSequences finds sequences of 18+ characters with high rare bigram ratio.
// This catches gibberish embedded in normal text while avoiding false positives on short random strings.
func findGibberishSequences(s string) []string {
	var sequences []string
	words := strings.Fields(s)

	for _, word := range words {
		// Skip words with high non-alpha ratio (like "qw#9mK$pL" - likely random tokens/passwords, not attacks)
		nonAlphaRatio := calculateNonAlphabeticRatio(word)
		if nonAlphaRatio > 0.25 {
			continue
		}

		// Check words/tokens that are 18+ chars (longer sequences are more reliably gibberish)
		if len(word) >= 18 {
			ratio := calculateRareBigramRatio(word)
			// If this word has >65% rare bigrams, it's likely gibberish
			if ratio > 0.65 {
				sequences = append(sequences, word)
			}
		}
	}

	return sequences
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
