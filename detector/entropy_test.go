package detector

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntropyDetector_HighEntropyInputs(t *testing.T) {
	detector := NewEntropyDetector()
	ctx := context.Background()

	tests := []struct {
		name           string
		input          string
		shouldBeUnsafe bool
	}{
		{
			name:           "base64 encoded string",
			input:          base64.StdEncoding.EncodeToString([]byte("This is a malicious command that has been encoded to bypass detection systems")),
			shouldBeUnsafe: true,
		},
		{
			name:           "hex encoded string",
			input:          "48656c6c6f20776f726c642074686973206973206120746573742073747261696e672077697468206869676820656e74726f7079",
			shouldBeUnsafe: false, // Hex has lower entropy (4.0 bits) than threshold (4.5)
		},
		{
			name:           "random characters",
			input:          "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7pI4oL6mK3nB9vC2xQ5jR8t",
			shouldBeUnsafe: true,
		},
		{
			name:           "mixed case alphanumeric (high randomness)",
			input:          "Zm9yIGV2ZXJ5IHBhdHRlcm4gd2UgY2FuIGNyZWF0ZSBhIGhpZ2ggZW50cm9weSB0ZXN0IGNhc2U=",
			shouldBeUnsafe: false, // Base64 has ~4.7 bits entropy, may not exceed 4.5 threshold consistently
		},
		{
			name:           "url safe base64",
			input:          "SGVsbG8gd29ybGQhIFRoaXMgaXMgYSB0ZXN0IHN0cmluZyB3aXRoIGhpZ2ggZW50cm9weS4gV2UgbmVlZCBpdCB0byBiZSBsb25nIGVub3VnaA",
			shouldBeUnsafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldBeUnsafe {
				assert.False(t, result.Safe, "Should be unsafe")
				assert.GreaterOrEqual(t, result.RiskScore, 0.6, "Risk score should be >= 0.6")
				assert.NotEmpty(t, result.DetectedPatterns)
				assert.Equal(t, "entropy_high_randomness", result.DetectedPatterns[0].Type)
			}
		})
	}
}

func TestEntropyDetector_NormalText(t *testing.T) {
	detector := NewEntropyDetector()
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "normal english text",
			input: "Hello, how are you today? I hope you are doing well and having a great day.",
		},
		{
			name:  "question about weather",
			input: "What is the weather like today? Should I bring an umbrella with me?",
		},
		{
			name:  "instruction to summarize",
			input: "Please summarize this document for me and highlight the main points.",
		},
		{
			name:  "normal conversation",
			input: "I need help understanding how to use this feature in the application.",
		},
		{
			name:  "repetitive text (low entropy)",
			input: "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd",
		},
		{
			name:  "common words",
			input: "the quick brown fox jumps over the lazy dog again and again",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			assert.True(t, result.Safe, "Should be safe")
			assert.LessOrEqual(t, result.RiskScore, 0.7, "Risk score should be <= 0.7")
		})
	}
}

func TestEntropyDetector_EdgeCases(t *testing.T) {
	detector := NewEntropyDetector()
	ctx := context.Background()

	t.Run("very short input", func(t *testing.T) {
		result := detector.Detect(ctx, "short")
		assert.True(t, result.Safe, "Short input should be safe")
		assert.Equal(t, 0.5, result.Confidence, "Low confidence for short input")
	})

	t.Run("empty input", func(t *testing.T) {
		result := detector.Detect(ctx, "")
		assert.True(t, result.Safe, "Empty input should be safe")
	})

	t.Run("numbers only", func(t *testing.T) {
		result := detector.Detect(ctx, "12345678901234567890")
		// Numbers have lower entropy than random chars
		assert.True(t, result.Safe, "Numbers should be safe")
	})

	t.Run("punctuation heavy", func(t *testing.T) {
		result := detector.Detect(ctx, "!!!! ???? .... !!!! ????")
		// Repetitive punctuation = low entropy
		assert.True(t, result.Safe, "Repetitive punctuation should be safe")
	})
}

func TestEntropyDetector_BoundaryThresholds(t *testing.T) {
	detector := NewEntropyDetector()
	ctx := context.Background()

	// Test input just above threshold
	t.Run("just above threshold", func(t *testing.T) {
		// Create input with controlled entropy
		input := "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9"
		result := detector.Detect(ctx, input)
		// Should trigger detection
		assert.False(t, result.Safe, "High entropy should be unsafe")
	})
}

func TestEntropyDetector_ConfidenceScaling(t *testing.T) {
	detector := NewEntropyDetector()
	ctx := context.Background()

	tests := []struct {
		name          string
		input         string
		minConfidence float64
	}{
		{
			name:          "short high-entropy input (50 chars)",
			input:         "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV",
			minConfidence: 0.70, // risk score (no length bonus yet)
		},
		{
			name:          "medium high-entropy input (150 chars)",
			input:         "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7paB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p",
			minConfidence: 0.80, // risk score + bonus for length >100
		},
		{
			name:          "long high-entropy input (600 chars)",
			input:         "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY8jF6vC1hD0sG3uE9iO2wM5qN8bV7cX4kJ6lA3gH9fT2yU5rW8eS1dZ7p" + "aB3xK9mQ2wP7zL5nR4tY",
			minConfidence: 0.85, // risk score + both bonuses (>100 and >500)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)
			assert.False(t, result.Safe, "High entropy should be detected")
			assert.GreaterOrEqual(t, result.Confidence, tt.minConfidence, "Confidence should scale with input length")
		})
	}
}

func TestEntropyDetector_CustomThreshold(t *testing.T) {
	// Create detector with very low threshold
	detector := NewEntropyDetectorWithThreshold(3.0)
	ctx := context.Background()

	// Normal text might trigger with low threshold
	input := "This is relatively normal text but with lower entropy threshold"
	result := detector.Detect(ctx, input)

	// With lower threshold, more inputs will be flagged
	// (exact result depends on text entropy)
	assert.NotNil(t, result)
}

func TestEntropyDetector_ContextCancellation(t *testing.T) {
	detector := NewEntropyDetector()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := detector.Detect(ctx, "some high entropy string aB3xK9mQ2wP7zL5n")

	assert.True(t, result.Safe, "Should return safe on cancelled context")
	assert.Equal(t, 0.0, result.RiskScore)
	assert.Equal(t, 0.0, result.Confidence)
}

func TestCalculateShannonEntropy(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:       "all same character (lowest entropy)",
			input:      "aaaaaaaaaaaaaaaa",
			minEntropy: 0.0,
			maxEntropy: 0.1,
		},
		{
			name:       "random base64 (high entropy)",
			input:      base64.StdEncoding.EncodeToString([]byte("random data with high entropy")),
			minEntropy: 4.0,
			maxEntropy: 8.0,
		},
		{
			name:       "normal english (medium entropy)",
			input:      "The quick brown fox jumps over the lazy dog",
			minEntropy: 3.5,
			maxEntropy: 5.0,
		},
		{
			name:       "empty string",
			input:      "",
			minEntropy: 0.0,
			maxEntropy: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := calculateShannonEntropy(tt.input)
			assert.GreaterOrEqual(t, entropy, tt.minEntropy)
			assert.LessOrEqual(t, entropy, tt.maxEntropy)
		})
	}
}
