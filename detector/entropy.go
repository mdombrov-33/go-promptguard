package detector

import (
	"context"
	"math"
)

// * EntropyDetector detects high-entropy inputs indicating obfuscation or encoding.
// * Uses Shannon entropy to measure randomness - high entropy suggests base64, hex, or encrypted content.
type EntropyDetector struct {
	threshold float64 //* Entropy threshold above which input is suspicious
}

func NewEntropyDetector() *EntropyDetector {
	return &EntropyDetector{
		threshold: 4.5, //* Default: 4.5 out of max 8.0 (binary)
	}
}

func NewEntropyDetectorWithThreshold(threshold float64) *EntropyDetector {
	return &EntropyDetector{
		threshold: threshold,
	}
}

func (d *EntropyDetector) Detect(ctx context.Context, input string) Result {
	patterns := []DetectedPatterns{}
	maxScore := 0.0

	select {
	case <-ctx.Done():
		return Result{Safe: true, RiskScore: 0.0, Confidence: 0.0}
	default:
	}

	//* Skip very short inputs (not enough data for entropy calculation)
	if len(input) < 20 {
		return Result{
			Safe:             true,
			RiskScore:        0.0,
			Confidence:       0.5,
			DetectedPatterns: nil,
		}
	}

	entropy := calculateShannonEntropy(input)

	//* Normalize entropy to 0-1 scale (max entropy is 8.0 for binary)
	normalizedEntropy := entropy / 8.0

	if entropy > d.threshold {
		//* Calculate risk score based on how far above threshold
		//* Higher entropy = higher risk
		riskScore := 0.6 + (normalizedEntropy-0.5)*0.8 //* Maps 0.5-1.0 entropy to 0.6-1.0 risk
		if riskScore > 1.0 {
			riskScore = 1.0
		}

		patterns = append(patterns, DetectedPatterns{
			Type:    "entropy_high_randomness",
			Score:   riskScore,
			Matches: []string{formatEntropyMatch(entropy)},
		})
		maxScore = riskScore
	}

	// * Calculate confidence based on input length (more data = higher confidence)
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

// * calculateShannonEntropy computes Shannon entropy of a string.
// * Returns value between 0 (perfectly predictable) and 8.0 (maximum randomness for byte data).
func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	//* Count frequency of each byte
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	//* Calculate entropy using Shannon formula: H = -Σ(p(x) * log2(p(x)))
	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		if count == 0 {
			continue
		}
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// * formatEntropyMatch creates a human-readable description of entropy detection.
func formatEntropyMatch(entropy float64) string {
	return "High entropy detected: " + formatFloat(entropy) + "/8.0"
}

// * formatFloat formats float to 2 decimal places as string.
func formatFloat(f float64) string {
	s := ""
	if f < 0 {
		s = "-"
		f = -f
	}

	intPart := int(f)
	s += itoa(intPart)

	f -= float64(intPart)
	f *= 100
	decPart := int(f + 0.5) //* Round

	s += "."
	if decPart < 10 {
		s += "0"
	}
	s += itoa(decPart)

	return s
}

// * itoa converts int to string without using strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	if i < 0 {
		return "-" + itoa(-i)
	}

	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}

	return string(digits)
}
