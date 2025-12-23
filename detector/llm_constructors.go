package detector

// NewOpenAIJudge creates an LLM judge for OpenAI API.
// Recommended model: "gpt-5"
func NewOpenAIJudge(apiKey, model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		"https://api.openai.com/v1/chat/completions",
		apiKey,
		model,
		opts...,
	)
}

// NewOpenRouterJudge creates an LLM judge for OpenRouter API.
// Provides access to 100+ models from different providers.
// Recommended models: x-ai/grok-code-fast-1, google/gemini-2.5-flash, anthropic/claude-sonnet-4.5
func NewOpenRouterJudge(apiKey, model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		"https://openrouter.ai/api/v1/chat/completions",
		apiKey,
		model,
		opts...,
	)
}

// NewOllamaJudge creates an LLM judge for local Ollama models.
// No API key required - runs locally.
// Recommended models: "llama3.2", "mistral", "phi3"
// Default endpoint: http://localhost:11434
func NewOllamaJudge(model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		"http://localhost:11434/v1/chat/completions",
		"", //* Ollama doesn't require API key
		model,
		opts...,
	)
}

// NewOllamaJudgeWithEndpoint creates an Ollama judge with custom endpoint.
// Useful if Ollama is running on a different host/port.
func NewOllamaJudgeWithEndpoint(endpoint, model string, opts ...LLMJudgeOption) LLMJudge {
	return NewGenericLLMJudge(
		endpoint+"/v1/chat/completions",
		"",
		model,
		opts...,
	)
}

