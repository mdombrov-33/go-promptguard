package detector

// DetectionMode represents the aggressiveness level of certain detectors.
type DetectionMode int

const (
	// ModeBalanced provides balanced detection with fewer false positives.
	ModeBalanced DetectionMode = iota
	// ModeAggressive provides stricter detection, may have more false positives.
	ModeAggressive
)

type Config struct {
	// 0.0 to 1.0.
	// Default: 0.7.
	Threshold float64

	// Default: true.
	EnableRoleInjection bool

	// Default: true.
	EnablePromptLeak bool

	// Default: true.
	EnableInstructionOverride bool

	// Default: true.
	EnableObfuscation bool

	// Default: true.
	EnableEntropy bool

	// Default: true.
	EnablePerplexity bool

	// Default: true.
	EnableTokenAnomaly bool

	// Default: true.
	EnableNormalization bool

	// Default: ModeBalanced.
	NormalizationMode DetectionMode

	// Default: true.
	EnableDelimiter bool

	// Default: ModeBalanced.
	DelimiterMode DetectionMode

	// Inputs longer than this will be truncated.
	// Default: 0 (no limit).
	MaxInputLength int

	// Default: nil (disabled).
	LLMJudge LLMJudge

	// Options: LLMAlways, LLMConditional, LLMFallback.
	// Default: LLMAlways.
	LLMRunMode LLMRunMode
}

type Option func(*Config)

func defaultConfig() Config {
	return Config{
		Threshold:                 0.7,
		EnableRoleInjection:       true,
		EnablePromptLeak:          true,
		EnableInstructionOverride: true,
		EnableObfuscation:         true,
		EnableEntropy:             true,
		EnablePerplexity:          true,
		EnableTokenAnomaly:        true,
		EnableNormalization:       true,
		NormalizationMode:         ModeBalanced,
		EnableDelimiter:           true,
		DelimiterMode:             ModeBalanced,
		MaxInputLength:            0,
		LLMJudge:                  nil,
		LLMRunMode:                LLMAlways,
	}
}

// WithThreshold sets the risk score threshold for unsafe classification.
// Inputs with risk scores >= threshold are considered unsafe.
func WithThreshold(threshold float64) Option {
	return func(c *Config) {
		if threshold >= 0.0 && threshold <= 1.0 {
			c.Threshold = threshold
		}
	}
}

// WithRoleInjection enables or disables role injection detection.
func WithRoleInjection(enabled bool) Option {
	return func(c *Config) {
		c.EnableRoleInjection = enabled
	}
}

// WithPromptLeak enables or disables prompt leak detection.
func WithPromptLeak(enabled bool) Option {
	return func(c *Config) {
		c.EnablePromptLeak = enabled
	}
}

// WithInstructionOverride enables or disables instruction override detection.
func WithInstructionOverride(enabled bool) Option {
	return func(c *Config) {
		c.EnableInstructionOverride = enabled
	}
}

// WithObfuscation enables or disables obfuscation detection.
func WithObfuscation(enabled bool) Option {
	return func(c *Config) {
		c.EnableObfuscation = enabled
	}
}

// WithEntropy enables or disables entropy-based detection.
func WithEntropy(enabled bool) Option {
	return func(c *Config) {
		c.EnableEntropy = enabled
	}
}

// WithPerplexity enables or disables perplexity-based detection.
func WithPerplexity(enabled bool) Option {
	return func(c *Config) {
		c.EnablePerplexity = enabled
	}
}

// WithTokenAnomaly enables or disables token anomaly detection.
func WithTokenAnomaly(enabled bool) Option {
	return func(c *Config) {
		c.EnableTokenAnomaly = enabled
	}
}

// WithMaxInputLength sets the maximum input length to process.
// Set to 0 for no limit.
func WithMaxInputLength(maxLength int) Option {
	return func(c *Config) {
		if maxLength >= 0 {
			c.MaxInputLength = maxLength
		}
	}
}

// WithNormalization enables or disables character-level normalization detection.
func WithNormalization(enabled bool) Option {
	return func(c *Config) {
		c.EnableNormalization = enabled
	}
}

// WithNormalizationMode sets the normalization detection mode.
// Modes:
//   - ModeBalanced (default): Removes dots, dashes, underscores between single characters.
//   - ModeAggressive: Also removes spaces between single characters.
func WithNormalizationMode(mode DetectionMode) Option {
	return func(c *Config) {
		c.NormalizationMode = mode
	}
}

// WithDelimiter enables or disables delimiter/framing attack detection.
func WithDelimiter(enabled bool) Option {
	return func(c *Config) {
		c.EnableDelimiter = enabled
	}
}

// WithDelimiterMode sets the delimiter detection mode.
// Modes:
//   - ModeBalanced (default): Delimiter must be near attack keywords.
//   - ModeAggressive: Any delimiter pattern triggers detection.
func WithDelimiterMode(mode DetectionMode) Option {
	return func(c *Config) {
		c.DelimiterMode = mode
	}
}

// WithAllDetectors enables all available detectors.
func WithAllDetectors() Option {
	return func(c *Config) {
		c.EnableRoleInjection = true
		c.EnablePromptLeak = true
		c.EnableInstructionOverride = true
		c.EnableObfuscation = true
		c.EnableEntropy = true
		c.EnablePerplexity = true
		c.EnableTokenAnomaly = true
		c.EnableNormalization = true
		c.EnableDelimiter = true
	}
}

// WithLLM enables LLM-based detection with the specified judge and run mode.
// Modes:
//   - LLMAlways: Run on every input (most accurate, most expensive)
//   - LLMConditional: Run only when pattern-based detectors are uncertain (0.5-0.7 score).
//   - LLMFallback: Run only when pattern-based detectors say safe (double-check negatives).
func WithLLM(judge LLMJudge, mode LLMRunMode) Option {
	return func(c *Config) {
		c.LLMJudge = judge
		c.LLMRunMode = mode
	}
}
