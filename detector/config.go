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

	//* MaxInputLength is the maximum input length to process (in bytes).
	//* Inputs longer than this will be truncated. 0 means no limit.
	//* Default: 0 (no limit)
	MaxInputLength int
}

type Option func(*Config)

func defaultConfig() Config {
	return Config{
		Threshold:                 0.7,
		EnableRoleInjection:       true,
		EnablePromptLeak:          true,
		EnableInstructionOverride: true,
		EnableObfuscation:         true,
		MaxInputLength:            0,
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

// * WithMaxInputLength sets the maximum input length to process.
// * Set to 0 for no limit.
func WithMaxInputLength(maxLength int) Option {
	return func(c *Config) {
		if maxLength >= 0 {
			c.MaxInputLength = maxLength
		}
	}
}

// * WithAllDetectors enables all available detectors (including unimplemented ones).
func WithAllDetectors() Option {
	return func(c *Config) {
		c.EnableRoleInjection = true
		c.EnablePromptLeak = true
		c.EnableInstructionOverride = true
		c.EnableObfuscation = true
	}
}

// * WithOnlyRoleInjection enables only role injection detection.
func WithOnlyRoleInjection() Option {
	return func(c *Config) {
		c.EnableRoleInjection = true
		c.EnablePromptLeak = false
		c.EnableInstructionOverride = false
		c.EnableObfuscation = false
	}
}

// * WithOnlyPromptLeak enables only prompt leak detection.
func WithOnlyPromptLeak() Option {
	return func(c *Config) {
		c.EnableRoleInjection = false
		c.EnablePromptLeak = true
		c.EnableInstructionOverride = false
		c.EnableObfuscation = false
	}
}
