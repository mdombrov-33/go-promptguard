package detector

// NewOpenAIJudge creates an LLM judge for OpenAI API
func NewOpenAIJudge(apiKey, model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		"https://api.openai.com/v1/chat/completions",
		apiKey,
		model,
		opts...,
	)
}

// NewOpenRouterJudge creates an LLM judge for OpenRouter API
func NewOpenRouterJudge(apiKey, model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		"https://openrouter.ai/api/v1/chat/completions",
		apiKey,
		model,
		opts...,
	)
}

// NewOllamaJudge creates an LLM judge for local Ollama models
// Default endpoint: http://localhost:11434
func NewOllamaJudge(model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		"http://localhost:11434/v1/chat/completions",
		"", // Ollama doesn't require API key
		model,
		opts...,
	)
}

// NewOllamaJudgeWithEndpoint creates an Ollama judge with custom endpoint
// Useful if Ollama is running on a different host/port
func NewOllamaJudgeWithEndpoint(endpoint, model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		endpoint+"/v1/chat/completions",
		"",
		model,
		opts...,
	)
}
