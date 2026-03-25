package main

import (
	"context"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mdombrov-33/go-promptguard/detector"
)

type screen int

const (
	menuScreen screen = iota
	checkScreen
	resultsScreen
	batchScreen
	batchResultsScreen
	settingsScreen
	aboutScreen
)

type model struct {
	screen             screen
	menuChoice         int
	input              textinput.Model
	fileInput          textinput.Model
	result             *detector.Result
	lastInput          string
	guard              *detector.MultiDetector
	threshold          float64
	enableRoleInj      bool
	enablePromptLeak   bool
	enableInstOverride bool
	enableObfuscation  bool
	enableNorm         bool
	normMode           detector.DetectionMode
	enableDelim        bool
	delimMode          detector.DetectionMode
	enableEntropy      bool
	enablePerp         bool
	enableToken        bool
	enableLLM          bool
	llmMode            int
	llmProvider        string
	availableProviders []string
	width              int
	height             int
	batchSummary       *BatchSummary
	batchProgress      int
	batchTotal         int
	batchProcessing    bool
	batchError         error
	checking           bool
	settingsChoice     int
}

func initialModel() model {
	ti := textinput.New()
	ti.Placeholder = "Enter text to check..."
	ti.CharLimit = 1000
	ti.Width = 60

	fi := textinput.New()
	fi.Placeholder = "Enter file path..."
	fi.CharLimit = 500
	fi.Width = 60

	availableProviders := []string{"none"}
	defaultProvider := "none"

	if os.Getenv("OPENAI_API_KEY") != "" {
		availableProviders = append(availableProviders, "openai")
		if defaultProvider == "none" {
			defaultProvider = "openai"
		}
	}
	if os.Getenv("OPENROUTER_API_KEY") != "" {
		availableProviders = append(availableProviders, "openrouter")
		if defaultProvider == "none" {
			defaultProvider = "openrouter"
		}
	}
	availableProviders = append(availableProviders, "ollama")
	if defaultProvider == "none" {
		defaultProvider = "ollama"
	}

	savedCfg, _ := loadConfig()

	m := model{
		screen:             menuScreen,
		menuChoice:         0,
		input:              ti,
		fileInput:          fi,
		threshold:          0.7,
		enableRoleInj:      true,
		enablePromptLeak:   true,
		enableInstOverride: true,
		enableObfuscation:  true,
		enableNorm:         true,
		normMode:           detector.ModeBalanced,
		enableDelim:        true,
		delimMode:          detector.ModeBalanced,
		enableEntropy:      true,
		enablePerp:         true,
		enableToken:        true,
		enableLLM:          false,
		llmMode:            1,
		llmProvider:        defaultProvider,
		availableProviders: availableProviders,
	}

	if savedCfg != nil {
		m.threshold = savedCfg.Threshold
		m.enableRoleInj = savedCfg.EnableRoleInj
		m.enablePromptLeak = savedCfg.EnablePromptLeak
		m.enableInstOverride = savedCfg.EnableInstOverride
		m.enableObfuscation = savedCfg.EnableObfuscation
		m.enableNorm = savedCfg.EnableNorm
		m.normMode = savedCfg.NormMode
		m.enableDelim = savedCfg.EnableDelim
		m.delimMode = savedCfg.DelimMode
		m.enableEntropy = savedCfg.EnableEntropy
		m.enablePerp = savedCfg.EnablePerp
		m.enableToken = savedCfg.EnableToken
		m.enableLLM = savedCfg.EnableLLM
		m.llmMode = savedCfg.LLMMode
		for _, p := range availableProviders {
			if p == savedCfg.LLMProvider {
				m.llmProvider = savedCfg.LLMProvider
				break
			}
		}
	}

	m.updateGuard()
	return m
}

func (m *model) updateGuard() {
	opts := []detector.Option{
		detector.WithThreshold(m.threshold),
		detector.WithRoleInjection(m.enableRoleInj),
		detector.WithPromptLeak(m.enablePromptLeak),
		detector.WithInstructionOverride(m.enableInstOverride),
		detector.WithObfuscation(m.enableObfuscation),
		detector.WithNormalization(m.enableNorm),
		detector.WithNormalizationMode(m.normMode),
		detector.WithDelimiter(m.enableDelim),
		detector.WithDelimiterMode(m.delimMode),
		detector.WithEntropy(m.enableEntropy),
		detector.WithPerplexity(m.enablePerp),
		detector.WithTokenAnomaly(m.enableToken),
	}

	if m.enableLLM && m.llmProvider != "" && m.llmProvider != "none" {
		var judge detector.LLMJudge
		switch m.llmProvider {
		case "openai":
			model := os.Getenv("OPENAI_MODEL")
			if model == "" {
				model = "gpt-5"
			}
			judge = detector.NewOpenAIJudge(os.Getenv("OPENAI_API_KEY"), model,
				detector.WithOutputFormat(detector.LLMStructured))
		case "openrouter":
			model := os.Getenv("OPENROUTER_MODEL")
			if model == "" {
				model = "anthropic/claude-sonnet-4.5"
			}
			judge = detector.NewOpenRouterJudge(os.Getenv("OPENROUTER_API_KEY"), model,
				detector.WithOutputFormat(detector.LLMStructured))
		case "ollama":
			ollamaHost := os.Getenv("OLLAMA_HOST")
			if ollamaHost == "" {
				ollamaHost = os.Getenv("OLLAMA_API_BASE")
			}

			ollamaModel := os.Getenv("OLLAMA_MODEL")
			if ollamaModel == "" {
				ollamaModel = "llama3.1:8b"
			}

			if ollamaHost != "" {
				judge = detector.NewOllamaJudgeWithEndpoint(ollamaHost, ollamaModel,
					detector.WithLLMTimeout(60*time.Second),
					detector.WithOutputFormat(detector.LLMStructured))
			} else {
				judge = detector.NewOllamaJudge(ollamaModel,
					detector.WithLLMTimeout(60*time.Second),
					detector.WithOutputFormat(detector.LLMStructured))
			}
		}

		if judge != nil {
			go judge.Warmup(context.Background())

			var mode detector.LLMRunMode
			switch m.llmMode {
			case 0:
				mode = detector.LLMAlways
			case 1:
				mode = detector.LLMConditional
			case 2:
				mode = detector.LLMFallback
			default:
				mode = detector.LLMConditional
			}
			opts = append(opts, detector.WithLLM(judge, mode))
		}
	}

	m.guard = detector.New(opts...)
}

func (m model) Init() tea.Cmd {
	return nil
}
