package detector

// * Config holds configuration for the multi-detector.
type Config struct {
	//* Threshold is the risk score above which input is considered unsafe (0.0-1.0).
	//* Default: 0.7
	Threshold float64

	//* EnableRoleInjection enables detection of role injection attacks.
	//* Default: true
	EnableRoleInjection bool

	//* EnablePromptLeak enables detection of system prompt leakage attempts.
	//* Default: true
	EnablePromptLeak bool

	//* EnableInstructionOverride enables detection of instruction override attacks.
	//* Default: true
	EnableInstructionOverride bool

	//* EnableObfuscation enables detection of obfuscated payloads.
	//* Default: true
	EnableObfuscation bool

	//* EnableEntropy enables detection of high-entropy inputs (encoding/obfuscation).
	//* Default: true
	EnableEntropy bool

	//* EnablePerplexity enables detection of unnatural text patterns.
	//* Default: true
	EnablePerplexity bool

	//* EnableTokenAnomaly enables detection of Unicode and character distribution anomalies.
	//* Default: true
	EnableTokenAnomaly bool

	//* MaxInputLength is the maximum input length to process (in bytes).
	//* Inputs longer than this will be truncated. 0 means no limit.
	//* Default: 0 (no limit)
	MaxInputLength int

	//* LLMJudge is the LLM-based detector (optional, disabled by default).
	//* Set using WithLLM() to enable LLM-based detection.
	LLMJudge LLMJudge

	//* LLMRunMode determines when the LLM detector runs.
	//* Default: LLMAlways
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
		MaxInputLength:            0,
		LLMJudge:                  nil, // Disabled by default
		LLMRunMode:                LLMAlways,
	}
}

// * WithThreshold sets the risk score threshold (0.0-1.0).
// * Inputs with risk scores >= threshold are considered unsafe.
func WithThreshold(threshold float64) Option {
	return func(c *Config) {
		if threshold >= 0.0 && threshold <= 1.0 {
			c.Threshold = threshold
		}
	}
}

// * WithRoleInjection enables or disables role injection detection.
func WithRoleInjection(enabled bool) Option {
	return func(c *Config) {
		c.EnableRoleInjection = enabled
	}
}

// * WithPromptLeak enables or disables prompt leak detection.
func WithPromptLeak(enabled bool) Option {
	return func(c *Config) {
		c.EnablePromptLeak = enabled
	}
}

// * WithInstructionOverride enables or disables instruction override detection.
func WithInstructionOverride(enabled bool) Option {
	return func(c *Config) {
		c.EnableInstructionOverride = enabled
	}
}

// * WithObfuscation enables or disables obfuscation detection.
func WithObfuscation(enabled bool) Option {
	return func(c *Config) {
		c.EnableObfuscation = enabled
	}
}

// * WithEntropy enables or disables entropy-based detection.
func WithEntropy(enabled bool) Option {
	return func(c *Config) {
		c.EnableEntropy = enabled
	}
}

// * WithPerplexity enables or disables perplexity-based detection.
func WithPerplexity(enabled bool) Option {
	return func(c *Config) {
		c.EnablePerplexity = enabled
	}
}

// * WithTokenAnomaly enables or disables token anomaly detection.
func WithTokenAnomaly(enabled bool) Option {
	return func(c *Config) {
		c.EnableTokenAnomaly = enabled
	}
}

// * WithMaxInputLength sets the maximum input length to process.
// * Set to 0 for no limit.
func WithMaxInputLength(maxLength int) Option {
	return func(c *Config) {
		if maxLength >= 0 {
			c.MaxInputLength = maxLength
		}
	}
}

// * WithAllDetectors enables all available detectors.
func WithAllDetectors() Option {
	return func(c *Config) {
		c.EnableRoleInjection = true
		c.EnablePromptLeak = true
		c.EnableInstructionOverride = true
		c.EnableObfuscation = true
		c.EnableEntropy = true
		c.EnablePerplexity = true
		c.EnableTokenAnomaly = true
	}
}

// * WithLLM enables LLM-based detection with the specified judge and run mode.
// * LLM detection is disabled by default (expensive, slower).
// * Run modes:
// *   - LLMAlways: Run on every input (most accurate, most expensive)
// *   - LLMConditional: Run only when pattern-based detectors are uncertain (0.5-0.7 score)
// *   - LLMFallback: Run only when pattern-based detectors say safe (double-check negatives)
func WithLLM(judge LLMJudge, mode LLMRunMode) Option {
	return func(c *Config) {
		c.LLMJudge = judge
		c.LLMRunMode = mode
	}
}

