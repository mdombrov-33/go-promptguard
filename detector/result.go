package detector

// Result represents the detection result from analyzing an input
type Result struct {
	Safe             bool    // true = safe, false = malicious
	RiskScore        float64 // 0.0 - 1.0 risk score
	Confidence       float64 // 0.0 - 1.0 confidence score
	DetectedPatterns []DetectedPattern
	LLMResult        *LLMResult // Optional LLM-specific data (only set when using LLM detection)
}

// DetectedPattern contains information about a specific pattern detected in the input
type DetectedPattern struct {
	Type    string   // 'role_injection', 'prompt_leak', etc
	Score   float64  // risk score from this pattern
	Matches []string // actual text fragments that matched
}

func (r *Result) IsHighRisk() bool {
	return r.RiskScore >= 0.7
}
