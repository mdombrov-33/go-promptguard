package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GenericLLMJudge implements LLMJudge using OpenAI-compatible API endpoints
type GenericLLMJudge struct {
	endpoint     string
	apiKey       string
	model        string
	outputFormat LLMOutputFormat
	systemPrompt string
	timeout      time.Duration
	httpClient   *http.Client
}

func NewGenericLLMJudge(endpoint, apiKey, model string, opts ...LLMJudgeOption) *GenericLLMJudge {
	judge := &GenericLLMJudge{
		endpoint:     endpoint,
		apiKey:       apiKey,
		model:        model,
		outputFormat: LLMSimple, // Default to cheap mode
		systemPrompt: "",        // Will be set based on format
		timeout:      10 * time.Second,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(judge)
	}

	if judge.systemPrompt == "" {
		if judge.outputFormat == LLMSimple {
			judge.systemPrompt = defaultSimplePrompt()
		} else {
			judge.systemPrompt = defaultStructuredPrompt()
		}
	}

	return judge
}

// GetTimeout returns the configured timeout
func (j *GenericLLMJudge) GetTimeout() time.Duration {
	return j.timeout
}

// GetOutputFormat returns the configured output format
func (j *GenericLLMJudge) GetOutputFormat() LLMOutputFormat {
	return j.outputFormat
}

// GetSystemPrompt returns the configured system prompt
func (j *GenericLLMJudge) GetSystemPrompt() string {
	return j.systemPrompt
}

// Judge sends the input to the LLM API and returns the classification result
func (j *GenericLLMJudge) Judge(ctx context.Context, input string) (LLMResult, error) {
	payload := map[string]interface{}{
		"model": j.model,
		"messages": []map[string]string{
			{"role": "system", "content": j.systemPrompt},
			{"role": "user", "content": buildUserPrompt(input)},
		},
		"temperature": 1,
	}

	if j.outputFormat == LLMStructured {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return LLMResult{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", j.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return LLMResult{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if j.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+j.apiKey)
	}

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return LLMResult{}, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return LLMResult{}, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return LLMResult{}, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return LLMResult{}, fmt.Errorf("no response from LLM")
	}

	content := strings.TrimSpace(apiResp.Choices[0].Message.Content)

	if j.outputFormat == LLMSimple {
		return parseSimpleResponse(content)
	}
	return parseStructuredResponse(content)
}

// parseSimpleResponse parses "SAFE" or "ATTACK" responses.
func parseSimpleResponse(content string) (LLMResult, error) {
	upper := strings.ToUpper(content)

	if strings.Contains(upper, "ATTACK") {
		return LLMResult{
			IsAttack:   true,
			Confidence: 0.9, // High confidence for clear classification
		}, nil
	}

	if strings.Contains(upper, "SAFE") {
		return LLMResult{
			IsAttack:   false,
			Confidence: 0.9,
		}, nil
	}

	return LLMResult{}, fmt.Errorf("unexpected response: %s", content)
}

func parseStructuredResponse(content string) (LLMResult, error) {
	var resp struct {
		IsAttack   bool    `json:"is_attack"`
		Confidence float64 `json:"confidence"`
		AttackType string  `json:"attack_type"`
		Reasoning  string  `json:"reasoning"`
	}

	if err := json.Unmarshal([]byte(content), &resp); err != nil {
		return LLMResult{}, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return LLMResult{
		IsAttack:   resp.IsAttack,
		Confidence: resp.Confidence,
		AttackType: resp.AttackType,
		Reasoning:  resp.Reasoning,
	}, nil
}
