package detector

import "strings"

// detectorWeights maps detector category (pattern type prefix) to a trust weight.
// Higher weight = we trust this detector's score more.
// Strong semantic detectors (role_injection, prompt_leak, instruction_override) get 1.0
// because when they fire, the signal is almost always real.
// Statistical detectors (entropy, perplexity, token_anomaly) get lower weights
// because they produce more noise and should not flag inputs on their own.
var detectorWeights = map[string]float64{
	"role_injection":         1.00,
	"prompt_leak":            1.00,
	"instruction_override":   1.00,
	"normalization":          0.90,
	"obfuscation":            0.90,
	"delimiter":              0.85,
	"entropy":                0.55,
	"perplexity":             0.50,
	"token_anomaly":          0.45,
	"llm":                    1.00, // LLM judge is high-trust — pass its confidence through unchanged
}

const defaultWeight = 0.70

// weightForPattern returns the weight for a detected pattern based on its type prefix.
// Pattern types follow the format "category_subtype" (e.g. "role_injection_special_token").
func weightForPattern(patternType string) float64 {
	for category, weight := range detectorWeights {
		if strings.HasPrefix(patternType, category) {
			return weight
		}
	}
	return defaultWeight
}

// computeWeightedScore replaces the old "max + 0.1 bonus" algorithm.
//
// Formula: final = min(Σ(score_i × weight_i), 1.0)
//
// Each detector that fires contributes score × weight to the total.
// Strong detectors (weight ~1.0) pass their score through nearly unchanged.
// Weak detectors (weight ~0.5) are discounted, so they cannot cross the
// threshold alone at borderline scores but do reinforce stronger signals.
func computeWeightedScore(patterns []DetectedPattern) float64 {
	if len(patterns) == 0 {
		return 0.0
	}

	// Deduplicate by detector category so a single detector firing multiple
	// sub-patterns (e.g. obfuscation_base64 + obfuscation_hex in one input)
	// doesn't count its weight multiple times.
	bestPerCategory := make(map[string]float64)
	for _, p := range patterns {
		category := patternCategory(p.Type)
		if p.Score > bestPerCategory[category] {
			bestPerCategory[category] = p.Score
		}
	}

	total := 0.0
	for category, score := range bestPerCategory {
		w := detectorWeights[category]
		if w == 0 {
			w = defaultWeight
		}
		total += score * w
	}

	if total > 1.0 {
		return 1.0
	}
	return round(total, 2)
}

// patternCategory extracts the detector category from a pattern type string.
// "role_injection_special_token" → "role_injection"
// "entropy_high_randomness"      → "entropy"
func patternCategory(patternType string) string {
	for category := range detectorWeights {
		if strings.HasPrefix(patternType, category) {
			return category
		}
	}
	// Fallback: use everything before the last underscore segment
	if idx := strings.LastIndex(patternType, "_"); idx > 0 {
		return patternType[:idx]
	}
	return patternType
}
