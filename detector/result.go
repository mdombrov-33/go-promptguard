package detector

// Result represents the detection result from analyzing an input.
type Result struct {
	Safe             bool    //* true = safe, false = malicious
	RiskScore        float64 //* 0.0 - 1.0 risk score
	Confidence       float64 //* 0.0 - 1.0 confidence score
	DetectedPatterns []DetectedPatterns
}

// DetectedPatterns contains information about a specific pattern detected in the input.
type DetectedPatterns struct {
	Type    string   //* 'role_injection', 'prompt_leak', etc.
	Score   float64  //* risk score from this pattern
	Matches []string //* actual text fragments that matched
}

// IsHighRisk returns true if the risk score is >= 0.7.
func (r *Result) IsHighRisk() bool {
	return r.RiskScore >= 0.7
}
