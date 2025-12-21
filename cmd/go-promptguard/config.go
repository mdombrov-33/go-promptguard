package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type SavedConfig struct {
	Threshold          float64 `json:"threshold"`
	EnableRoleInj      bool    `json:"enable_role_injection"`
	EnablePromptLeak   bool    `json:"enable_prompt_leak"`
	EnableInstOverride bool    `json:"enable_instruction_override"`
	EnableObfuscation  bool    `json:"enable_obfuscation"`
	EnableEntropy      bool    `json:"enable_entropy"`
	EnablePerp         bool    `json:"enable_perplexity"`
	EnableToken        bool    `json:"enable_token_anomaly"`
	EnableLLM          bool    `json:"enable_llm"`
	LLMMode            int     `json:"llm_mode"`
	LLMProvider        string  `json:"llm_provider"`
}

func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configDir := filepath.Join(home, ".config", "go-promptguard")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.json"), nil
}

func saveConfig(m *model) error {
	cfg := SavedConfig{
		Threshold:          m.threshold,
		EnableRoleInj:      m.enableRoleInj,
		EnablePromptLeak:   m.enablePromptLeak,
		EnableInstOverride: m.enableInstOverride,
		EnableObfuscation:  m.enableObfuscation,
		EnableEntropy:      m.enableEntropy,
		EnablePerp:         m.enablePerp,
		EnableToken:        m.enableToken,
		EnableLLM:          m.enableLLM,
		LLMMode:            m.llmMode,
		LLMProvider:        m.llmProvider,
	}

	path, err := getConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func loadConfig() (*SavedConfig, error) {
	path, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cfg SavedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
