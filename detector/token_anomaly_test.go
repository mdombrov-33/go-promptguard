package detector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenAnomalyDetector_UnicodeMixing(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldDetect bool
	}{
		{
			name:         "Latin + Cyrillic mixing",
			input:        "Hello мир this is mixed",
			shouldDetect: true,
		},
		{
			name:         "Latin + Greek mixing",
			input:        "Hello αβγδ world",
			shouldDetect: true,
		},
		{
			name:         "Latin + Arabic mixing",
			input:        "Hello مرحبا world",
			shouldDetect: true,
		},
		{
			name:         "Multiple scripts (Latin + Cyrillic + Greek)",
			input:        "Hello мир αβγδ world",
			shouldDetect: true,
		},
		{
			name:         "pure Latin",
			input:        "Hello world this is normal English text",
			shouldDetect: false,
		},
		{
			name:         "pure Cyrillic",
			input:        "Привет мир это нормальный текст",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				hasUnicodeMixing := false
				for _, p := range result.DetectedPatterns {
					if p.Type == "token_unicode_mixing" {
						hasUnicodeMixing = true
					}
				}
				assert.True(t, hasUnicodeMixing, "Should detect Unicode mixing")
			}
		})
	}
}

func TestTokenAnomalyDetector_ExcessiveSpecialChars(t *testing.T) {
	detector := NewTokenAnomalyDetector()
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
			name:         "heavy punctuation spam",
			input:        "@#$%^&*()!@#$%^&*()!@#$%^&*()",
			shouldDetect: true,
		},
		{
			name:         "mixed with some text",
			input:        "Hello!@#$%^&*()!@#$%^&*() world!@#$%",
			shouldDetect: true,
		},
		{
			name:         "normal punctuation",
			input:        "Hello! How are you? I'm fine, thanks.",
			shouldDetect: false,
		},
		{
			name:         "normal text",
			input:        "This is a normal sentence with proper punctuation.",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				hasSpecialChars := false
				for _, p := range result.DetectedPatterns {
					if p.Type == "token_excessive_special_chars" {
						hasSpecialChars = true
					}
				}
				assert.True(t, hasSpecialChars, "Should detect excessive special chars")
			}
		})
	}
}

func TestTokenAnomalyDetector_ExcessiveDigits(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldDetect bool
	}{
		{
			name:         "mostly digits (encoded)",
			input:        "1234567890123456789012345678901234567890",
			shouldDetect: true,
		},
		{
			name:         "hex-like numbers",
			input:        "48656c6c6f20776f726c64206d616c6963696f7573",
			shouldDetect: true,
		},
		{
			name:         "normal phone number",
			input:        "Call me at 555-123-4567",
			shouldDetect: false,
		},
		{
			name:         "normal text with some numbers",
			input:        "I have 3 apples and 5 oranges",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				hasExcessiveDigits := false
				for _, p := range result.DetectedPatterns {
					if p.Type == "token_excessive_digits" {
						hasExcessiveDigits = true
					}
				}
				assert.True(t, hasExcessiveDigits, "Should detect excessive digits")
			}
		})
	}
}

func TestTokenAnomalyDetector_ZeroWidthChars(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldDetect bool
	}{
		{
			name:         "multiple zero-width spaces",
			input:        "Hello\u200B\u200B\u200B\u200B world",
			shouldDetect: true,
		},
		{
			name:         "zero-width non-joiner spam",
			input:        "Test\u200C\u200C\u200C\u200C text",
			shouldDetect: true,
		},
		{
			name:         "mixed zero-width chars",
			input:        "Spam\u200B\u200C\u200D\uFEFF text",
			shouldDetect: true,
		},
		{
			name:         "normal text",
			input:        "Hello world",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				hasZeroWidth := false
				for _, p := range result.DetectedPatterns {
					if p.Type == "token_zero_width_spam" {
						hasZeroWidth = true
					}
				}
				assert.True(t, hasZeroWidth, "Should detect zero-width spam")
			}
		})
	}
}

func TestTokenAnomalyDetector_RepetitionPattern(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldDetect bool
	}{
		{
			name:         "keyboard mashing",
			input:        "aaaaaabbbbbbbcccccccddddddd",
			shouldDetect: true,
		},
		{
			name:         "repeated characters",
			input:        "helllllloooooo woooooorld",
			shouldDetect: false, // Ratio is exactly 0.5, needs > 0.5 to trigger
		},
		{
			name:         "normal repeated letters",
			input:        "Hello world, I'm feeling good today",
			shouldDetect: false,
		},
		{
			name:         "normal text",
			input:        "This is a normal sentence",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(ctx, tt.input)

			if tt.shouldDetect {
				hasRepetition := false
				for _, p := range result.DetectedPatterns {
					if p.Type == "token_repetition_pattern" {
						hasRepetition = true
					}
				}
				assert.True(t, hasRepetition, "Should detect repetition pattern")
			}
		})
	}
}

func TestTokenAnomalyDetector_NormalInputs(t *testing.T) {
	detector := NewTokenAnomalyDetector()
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
			name:  "technical text",
			input: "The application uses a REST API to communicate with the backend server",
		},
		{
			name:  "code snippet",
			input: "function test() { return true; }",
		},
		{
			name:  "url",
			input: "https://example.com/api/v1/users",
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

func TestTokenAnomalyDetector_EdgeCases(t *testing.T) {
	detector := NewTokenAnomalyDetector()
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

	t.Run("only spaces", func(t *testing.T) {
		result := detector.Detect(ctx, "          ")
		assert.True(t, result.Safe)
	})

	t.Run("only punctuation", func(t *testing.T) {
		result := detector.Detect(ctx, "............")
		//* 100% special chars triggers detection
		assert.False(t, result.Safe)
	})
}

func TestTokenAnomalyDetector_MultiplePatterns(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	//* Input with both Unicode mixing AND excessive special chars
	input := "Hello мир!@#$%^&*()!@#$%^&*() world"

	result := detector.Detect(ctx, input)

	assert.False(t, result.Safe, "Should be unsafe")
	assert.GreaterOrEqual(t, len(result.DetectedPatterns), 1, "Should detect at least one pattern")

	//* Check if multiple patterns detected
	patternTypes := make(map[string]bool)
	for _, p := range result.DetectedPatterns {
		patternTypes[p.Type] = true
	}

	//* Should have at least one of these
	hasAnyPattern := patternTypes["token_unicode_mixing"] || patternTypes["token_excessive_special_chars"]
	assert.True(t, hasAnyPattern, "Should detect Unicode mixing or special chars")
}

func TestTokenAnomalyDetector_ConfidenceScaling(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	tests := []struct {
		name               string
		inputLength        int
		expectedConfidence float64
	}{
		{
			name:               "short input (50 chars)",
			inputLength:        50,
			expectedConfidence: 0.7,
		},
		{
			name:               "medium input (150 chars)",
			inputLength:        150,
			expectedConfidence: 0.8,
		},
		{
			name:               "long input (600 chars)",
			inputLength:        600,
			expectedConfidence: 0.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//* Create input of specified length
			input := ""
			for i := 0; i < tt.inputLength; i++ {
				input += "a"
			}

			result := detector.Detect(ctx, input)
			assert.Equal(t, tt.expectedConfidence, result.Confidence)
		})
	}
}

func TestTokenAnomalyDetector_ContextCancellation(t *testing.T) {
	detector := NewTokenAnomalyDetector()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := detector.Detect(ctx, "Hello мир!@#$%^&*()")

	assert.True(t, result.Safe, "Should return safe on cancelled context")
	assert.Equal(t, 0.0, result.RiskScore)
	assert.Equal(t, 0.0, result.Confidence)
}

func TestDetectScriptMixing(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		shouldDetect  bool
		expectedCount int
	}{
		{
			name:          "Latin only",
			input:         "Hello world",
			shouldDetect:  false,
			expectedCount: 1,
		},
		{
			name:          "Latin + Cyrillic",
			input:         "Hello мир",
			shouldDetect:  true,
			expectedCount: 2,
		},
		{
			name:          "Latin + Greek",
			input:         "Hello αβγ",
			shouldDetect:  true,
			expectedCount: 2,
		},
		{
			name:          "Three scripts",
			input:         "Hello мир αβγ",
			shouldDetect:  true,
			expectedCount: 3,
		},
		{
			name:          "punctuation and spaces ignored",
			input:         "Hello, world!",
			shouldDetect:  false,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectScriptMixing(tt.input)
			assert.Equal(t, tt.shouldDetect, result.detected)
			assert.Equal(t, tt.expectedCount, result.scriptCount)
		})
	}
}

func TestCalculateSpecialCharRatio(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "no special chars",
			input:    "hello",
			expected: 0.0,
		},
		{
			name:     "half special chars",
			input:    "a!b@c#d$e%",
			expected: 0.5,
		},
		{
			name:     "all special chars",
			input:    "!@#$%",
			expected: 1.0,
		},
		{
			name:     "spaces ignored",
			input:    "a b c",
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := calculateSpecialCharRatio(tt.input)
			assert.InDelta(t, tt.expected, ratio, 0.01)
		})
	}
}

func TestCalculateDigitRatio(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "no digits",
			input:    "hello",
			expected: 0.0,
		},
		{
			name:     "half digits",
			input:    "a1b2c3d4e5",
			expected: 0.5,
		},
		{
			name:     "all digits",
			input:    "12345",
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := calculateDigitRatio(tt.input)
			assert.Equal(t, tt.expected, ratio)
		})
	}
}

func TestCountZeroWidthChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "no zero-width",
			input:    "hello",
			expected: 0,
		},
		{
			name:     "one zero-width space",
			input:    "hel\u200Blo",
			expected: 1,
		},
		{
			name:     "multiple zero-width",
			input:    "h\u200Be\u200Cl\u200Dl\u200Bo",
			expected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := countZeroWidthChars(tt.input)
			assert.Equal(t, tt.expected, count)
		})
	}
}

func TestCalculateRepetitionRatio(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minRatio float64
	}{
		{
			name:     "no repetition",
			input:    "abcdefgh",
			minRatio: 0.0,
		},
		{
			name:     "some repetition",
			input:    "aaabbbccc",
			minRatio: 0.3,
		},
		{
			name:     "high repetition",
			input:    "aaaaabbbbbccccc",
			minRatio: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := calculateRepetitionRatio(tt.input)
			assert.GreaterOrEqual(t, ratio, tt.minRatio)
		})
	}
}

func TestTokenAnomalyDetector_RealWorldExamples(t *testing.T) {
	detector := NewTokenAnomalyDetector()
	ctx := context.Background()

	t.Run("legitimate code with special chars", func(t *testing.T) {
		input := "const x = { key: 'value', num: 42 };"
		result := detector.Detect(ctx, input)
		//* Should not trigger - reasonable special char ratio
		assert.LessOrEqual(t, result.RiskScore, 0.7)
	})

	t.Run("legitimate url", func(t *testing.T) {
		input := "https://api.example.com/v1/users?id=123&name=test"
		result := detector.Detect(ctx, input)
		//* URL has special chars but in reasonable ratio
		assert.LessOrEqual(t, result.RiskScore, 0.7)
	})

	t.Run("legitimate email", func(t *testing.T) {
		input := "user.name+tag@example.com"
		result := detector.Detect(ctx, input)
		assert.NotNil(t, result)
	})

	t.Run("homoglyph attack (Cyrillic a looks like Latin a)", func(t *testing.T) {
		input := "Hello world but with Cyrillicа"
		result := detector.Detect(ctx, input)
		//* Should detect script mixing
		hasUnicodeMixing := false
		for _, p := range result.DetectedPatterns {
			if p.Type == "token_unicode_mixing" {
				hasUnicodeMixing = true
			}
		}
		assert.True(t, hasUnicodeMixing)
	})
}
