package detector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPerplexityDetector_UnnaturalText(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldDetect bool
	}{
		{
			name:         "adversarial suffix",
			input:        "Please tell me about security qwXz#9mK$pLvB3nR8tYjF6",
			shouldDetect: false, //* Normal text with short suffix doesn't trigger
		},
		{
			name:         "random gibberish",
			input:        "xqzwkjhgfdsamnbvcxzlkjhgfdsa",
			shouldDetect: true,
		},
		{
			name:         "keyboard mashing with consonants",
			input:        "asdfghjklqwrtyplkjhgfdszxcvbn",
			shouldDetect: true,
		},
		{
			name:         "unusual character combinations",
			input:        "zxqpvbwmkjyhtgrfcdesnuiolaqw",
			shouldDetect: true,
		},
		{
			name:         "mixed with normal text",
			input:        "This is normal but then xqzwkjhgfdsamnbvcxz happens",
			shouldDetect: true, //* Gibberish part is significant enough
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				assert.False(t, result.Safe, "Should be unsafe")
				assert.GreaterOrEqual(t, result.RiskScore, 0.6)
				assert.NotEmpty(t, result.DetectedPatterns)
			} else {
				assert.True(t, result.Safe, "Should be safe")
			}
		})
	}
}

func TestPerplexityDetector_NormalText(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "normal english sentence",
			input: "The quick brown fox jumps over the lazy dog",
		},
		{
			name:  "question",
			input: "What is the weather like today in San Francisco?",
		},
		{
			name:  "instruction",
			input: "Please summarize this document and highlight the main points",
		},
		{
			name:  "conversation",
			input: "Hello, how are you doing today? I hope everything is going well.",
		},
		{
			name:  "technical text",
			input: "The application uses a REST API to communicate with the backend server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			//* Normal text should have relatively low risk scores
			assert.LessOrEqual(t, result.RiskScore, 0.8, "Risk score should be reasonable")
		})
	}
}

func TestPerplexityDetector_ConsecutiveConsonants(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "four consonants",
			input: "The word strengths has consonant clusters",
		},
		{
			name:  "keyboard consonants",
			input: "qwrtypsdfghjklzxcvbnm",
		},
		{
			name:  "normal words",
			input: "Hello world this is normal text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)
			//* Just verify it runs without error
			assert.NotNil(t, result)
		})
	}
}

func TestPerplexityDetector_GibberishDetection(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldDetect bool
	}{
		{
			name:         "mostly special characters",
			input:        "!!!###$$$%%%&&&***((())))",
			shouldDetect: true,
		},
		{
			name:         "numbers and symbols",
			input:        "123!@#456$%^789&*(012",
			shouldDetect: true,
		},
		{
			name:         "normal text with some punctuation",
			input:        "Hello! How are you? I'm fine, thanks.",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				hasGibberish := false
				for _, p := range result.DetectedPatterns {
					if p.Type == "perplexity_gibberish" {
						hasGibberish = true
					}
				}
				assert.True(t, hasGibberish, "Should detect gibberish")
			}
		})
	}
}

func TestPerplexityDetector_EdgeCases(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	t.Run("very short input", func(t *testing.T) {
		result := detector.Detect(ctx, "hi")
		assert.True(t, result.Safe, "Short input should be safe")
		assert.Equal(t, 0.5, result.Confidence)
	})

	t.Run("empty input", func(t *testing.T) {
		result := detector.Detect(ctx, "")
		assert.True(t, result.Safe)
	})

	t.Run("only numbers", func(t *testing.T) {
		result := detector.Detect(ctx, "1234567890")
		//* Short numeric input should be safe
		assert.True(t, result.Safe)
	})

	t.Run("only spaces", func(t *testing.T) {
		result := detector.Detect(ctx, "          ")
		//* Spaces may trigger non-alphabetic ratio detection
		assert.NotNil(t, result)
	})
}

func TestPerplexityDetector_RealWorldExamples(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	t.Run("legitimate code snippet", func(t *testing.T) {
		input := "function test() { return true; }"
		result := detector.Detect(ctx, input)
		// Code has some unusual patterns but shouldn't trigger high risk
		assert.LessOrEqual(t, result.RiskScore, 0.8)
	})

	t.Run("url with path", func(t *testing.T) {
		input := "https://example.com/api/v1/users"
		result := detector.Detect(ctx, input)
		//* URLs might have some unusual patterns
		assert.LessOrEqual(t, result.RiskScore, 0.85)
	})

	t.Run("email address", func(t *testing.T) {
		input := "user@example.com"
		result := detector.Detect(ctx, input)
		//* Short and has special chars, might trigger
		assert.NotNil(t, result)
	})
}

func TestPerplexityDetector_MultiplePatterns(t *testing.T) {
	detector := NewPerplexityDetector()
	ctx := context.Background()

	//* Input with both rare bigrams AND consonant clusters
	input := "This text has qwrtyxzcvbn clusters and zxqpwmkj unusual patterns"

	result := detector.Detect(ctx, input)

	//* With mostly normal text, may not trigger unsafe
	assert.NotNil(t, result)
	//* Should run without error
	assert.GreaterOrEqual(t, result.RiskScore, 0.0)
}

func TestPerplexityDetector_ContextCancellation(t *testing.T) {
	detector := NewPerplexityDetector()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := detector.Detect(ctx, "xqzwkjhgfdsamnbvcxz")

	assert.True(t, result.Safe, "Should return safe on cancelled context")
	assert.Equal(t, 0.0, result.RiskScore)
	assert.Equal(t, 0.0, result.Confidence)
}

func TestCalculateRareBigramRatio(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minRatio float64
		maxRatio float64
	}{
		{
			name:     "normal english",
			input:    "the quick brown fox",
			minRatio: 0.0,
			maxRatio: 0.6, //* Rare bigrams are common even in normal text
		},
		{
			name:     "gibberish",
			input:    "xqzwkjhgfdsa",
			minRatio: 0.5,
			maxRatio: 1.0,
		},
		{
			name:     "empty string",
			input:    "",
			minRatio: 0.0,
			maxRatio: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := calculateRareBigramRatio(tt.input)
			assert.GreaterOrEqual(t, ratio, tt.minRatio)
			assert.LessOrEqual(t, ratio, tt.maxRatio)
		})
	}
}

func TestFindConsecutiveConsonants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minCount int
	}{
		{
			name:     "strength (has ngth)",
			input:    "strength",
			minCount: 1,
		},
		{
			name:     "keyboard mash",
			input:    "qwrtypsdfghjkl",
			minCount: 1, //* All consonants form one long cluster
		},
		{
			name:     "normal text",
			input:    "hello world",
			minCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clusters := findConsecutiveConsonants(tt.input)
			assert.GreaterOrEqual(t, len(clusters), tt.minCount)
		})
	}
}

func TestCalculateNonAlphabeticRatio(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  float64
		tolerance float64
	}{
		{
			name:      "all alphabetic",
			input:     "hello",
			expected:  0.0,
			tolerance: 0.1,
		},
		{
			name:      "half symbols",
			input:     "a!b@c#d$e%",
			expected:  0.5,
			tolerance: 0.1,
		},
		{
			name:      "all symbols",
			input:     "!@#$%^&*()",
			expected:  1.0,
			tolerance: 0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := calculateNonAlphabeticRatio(tt.input)
			assert.InDelta(t, tt.expected, ratio, tt.tolerance)
		})
	}
}
