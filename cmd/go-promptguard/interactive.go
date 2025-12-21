package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

var (
	primaryColor   = lipgloss.Color("#7D56F4")
	secondaryColor = lipgloss.Color("#00D9FF")
	safeColor      = lipgloss.Color("#04B575")
	warningColor   = lipgloss.Color("#FFA500")
	dangerColor    = lipgloss.Color("#EE6A70")
	mutedColor     = lipgloss.Color("#888888")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			Padding(0, 0).
			MarginBottom(1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			MarginBottom(1)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Bold(true).
			Padding(0, 1)

	normalStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Padding(0, 1)

	safeStyle = lipgloss.NewStyle().
			Foreground(safeColor).
			Bold(true)

	unsafeStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			MarginTop(2)

	sectionHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(secondaryColor).
				MarginBottom(1)
)

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
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		availableProviders = append(availableProviders, "anthropic")
		if defaultProvider == "none" {
			defaultProvider = "anthropic"
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
			judge = detector.NewOpenAIJudge(os.Getenv("OPENAI_API_KEY"), model)
		case "openrouter":
			model := os.Getenv("OPENROUTER_MODEL")
			if model == "" {
				model = "anthropic/claude-sonnet-4.5"
			}
			judge = detector.NewOpenRouterJudge(os.Getenv("OPENROUTER_API_KEY"), model)
		case "anthropic":
			model := os.Getenv("ANTHROPIC_MODEL")
			if model == "" {
				model = "claude-sonnet-4-5-20250929"
			}
			judge = detector.NewAnthropicJudge(os.Getenv("ANTHROPIC_API_KEY"), model)
		case "ollama":
			ollamaHost := os.Getenv("OLLAMA_HOST")
			if ollamaHost == "" {
				ollamaHost = os.Getenv("OLLAMA_API_BASE")
			}

			ollamaModel := os.Getenv("OLLAMA_MODEL")
			if ollamaModel == "" {
				ollamaModel = "llama3.1"
			}

			if ollamaHost != "" {
				judge = detector.NewOllamaJudgeWithEndpoint(ollamaHost, ollamaModel, detector.WithLLMTimeout(60*time.Second))
			} else {
				judge = detector.NewOllamaJudge(ollamaModel, detector.WithLLMTimeout(60*time.Second))
			}
		}

		if judge != nil {
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

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.screen == menuScreen {
				return m, tea.Quit
			}
			if msg.String() == "q" {
				m.screen = menuScreen
				m.input.SetValue("")
				return m, nil
			}

		case "esc":
			m.screen = menuScreen
			m.input.SetValue("")
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	switch m.screen {
	case menuScreen:
		return m.updateMenu(msg)
	case checkScreen:
		return m.updateCheck(msg)
	case resultsScreen:
		return m.updateResults(msg)
	case batchScreen:
		return m.updateBatch(msg)
	case batchResultsScreen:
		return m.updateBatchResults(msg)
	case settingsScreen:
		return m.updateSettings(msg)
	case aboutScreen:
		return m.updateAbout(msg)
	}

	return m, nil
}

func (m model) updateMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.menuChoice > 0 {
				m.menuChoice--
			}
		case "down", "j":
			if m.menuChoice < 4 {
				m.menuChoice++
			}
		case "enter":
			switch m.menuChoice {
			case 0: // Check Input
				m.screen = checkScreen
				m.input.Focus()
				return m, textinput.Blink
			case 1: // Batch Processing
				m.screen = batchScreen
				m.fileInput.Focus()
				return m, textinput.Blink
			case 2: // Settings
				m.screen = settingsScreen
			case 3: // About
				m.screen = aboutScreen
			case 4: // Exit
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m model) updateCheck(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.input.Value() != "" && !m.checking {
				m.lastInput = m.input.Value()
				m.checking = true
				return m, m.checkInputCmd()
			}
		}
	case checkCompleteMsg:
		m.result = msg.result
		m.screen = resultsScreen
		m.checking = false
		return m, nil
	}

	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) checkInputCmd() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		result := m.guard.Detect(ctx, m.lastInput)
		return checkCompleteMsg{result: &result}
	}
}

type checkCompleteMsg struct {
	result *detector.Result
}

func (m model) updateResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "space":
			m.screen = checkScreen
			m.input.SetValue("")
			m.input.Focus()
			return m, textinput.Blink
		}
	}
	return m, nil
}

func (m model) updateSettings(msg tea.Msg) (tea.Model, tea.Cmd) {
	changed := false

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if m.settingsChoice > 0 {
				m.settingsChoice--
			}
		case "down":
			if m.settingsChoice < 10 { // 0-10 = 11 settings total
				m.settingsChoice++
			}
		case "left":
			if m.settingsChoice == 0 {
				m.threshold = max(0.0, m.threshold-0.05)
				changed = true
			}
		case "right":
			if m.settingsChoice == 0 {
				m.threshold = min(1.0, m.threshold+0.05)
				changed = true
			}
		case "enter", " ":
			changed = m.toggleSetting(m.settingsChoice)
		case "1":
			m.enableRoleInj = !m.enableRoleInj
			changed = true
		case "2":
			m.enablePromptLeak = !m.enablePromptLeak
			changed = true
		case "3":
			m.enableInstOverride = !m.enableInstOverride
			changed = true
		case "4":
			m.enableObfuscation = !m.enableObfuscation
			changed = true
		case "5":
			m.enableEntropy = !m.enableEntropy
			changed = true
		case "6":
			m.enablePerp = !m.enablePerp
			changed = true
		case "7":
			m.enableToken = !m.enableToken
			changed = true
		case "8":
			m.enableLLM = !m.enableLLM
			changed = true
		case "9":
			m.llmMode = (m.llmMode + 1) % 3
			changed = true
		case "0":
			if len(m.availableProviders) > 0 {
				currentIdx := 0
				for i, p := range m.availableProviders {
					if p == m.llmProvider {
						currentIdx = i
						break
					}
				}
				currentIdx = (currentIdx + 1) % len(m.availableProviders)
				m.llmProvider = m.availableProviders[currentIdx]
				changed = true
			}
		}

		if changed {
			m.updateGuard()
			saveConfig(&m)
		}
	}
	return m, nil
}

func (m *model) toggleSetting(choice int) bool {
	switch choice {
	case 0:
		return false
	case 1:
		m.enableRoleInj = !m.enableRoleInj
		return true
	case 2:
		m.enablePromptLeak = !m.enablePromptLeak
		return true
	case 3:
		m.enableInstOverride = !m.enableInstOverride
		return true
	case 4:
		m.enableObfuscation = !m.enableObfuscation
		return true
	case 5:
		m.enableEntropy = !m.enableEntropy
		return true
	case 6:
		m.enablePerp = !m.enablePerp
		return true
	case 7:
		m.enableToken = !m.enableToken
		return true
	case 8:
		m.enableLLM = !m.enableLLM
		return true
	case 9:
		m.llmMode = (m.llmMode + 1) % 3
		return true
	case 10:
		if len(m.availableProviders) > 0 {
			currentIdx := 0
			for i, p := range m.availableProviders {
				if p == m.llmProvider {
					currentIdx = i
					break
				}
			}
			currentIdx = (currentIdx + 1) % len(m.availableProviders)
			m.llmProvider = m.availableProviders[currentIdx]
			return true
		}
	}
	return false
}

func (m model) updateAbout(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func (m model) updateBatch(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			filePath := m.fileInput.Value()
			if filePath != "" && !m.batchProcessing {
				m.batchProcessing = true
				m.batchError = nil
				return m, m.processBatchCmd(filePath)
			}
		}
	case batchCompleteMsg:
		m.batchSummary = msg.summary
		m.screen = batchResultsScreen
		m.batchProcessing = false
		return m, nil
	case batchErrorMsg:
		m.batchProcessing = false
		m.batchError = msg.err
		return m, nil
	}

	m.fileInput, cmd = m.fileInput.Update(msg)
	return m, cmd
}

func (m model) processBatchCmd(filePath string) tea.Cmd {
	return func() tea.Msg {
		summary, err := ProcessBatch(filePath, m.guard, nil)
		if err != nil {
			return batchErrorMsg{err: err}
		}
		return batchCompleteMsg{summary: summary}
	}
}

type batchCompleteMsg struct {
	summary *BatchSummary
}

type batchErrorMsg struct {
	err error
}

func (m model) updateBatchResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "s":
			if m.batchSummary != nil {
				timestamp := time.Now().Format("2006-01-02_15-04-05")
				filename := fmt.Sprintf("batch_results/results_%s.csv", timestamp)
				ExportResults(m.batchSummary, filename)
			}
		case "j":
			if m.batchSummary != nil {
				timestamp := time.Now().Format("2006-01-02_15-04-05")
				filename := fmt.Sprintf("batch_results/results_%s.json", timestamp)
				ExportResults(m.batchSummary, filename)
			}
		case "enter", "space":
			m.screen = batchScreen
			m.fileInput.SetValue("")
			m.fileInput.Focus()
			m.batchProcessing = false
			return m, textinput.Blink
		}
	case batchCompleteMsg:
		m.batchSummary = msg.summary
		m.screen = batchResultsScreen
		m.batchProcessing = false
	case batchErrorMsg:
		m.batchProcessing = false
	}
	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case menuScreen:
		return m.viewMenu()
	case checkScreen:
		return m.viewCheck()
	case resultsScreen:
		return m.viewResults()
	case batchScreen:
		return m.viewBatch()
	case batchResultsScreen:
		return m.viewBatchResults()
	case settingsScreen:
		return m.viewSettings()
	case aboutScreen:
		return m.viewAbout()
	}
	return ""
}

func (m model) viewMenu() string {
	var s strings.Builder

	header := titleStyle.Render("go-promptguard")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, header))
	s.WriteString("\n\n")

	menuPanel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
		Padding(2, 3).
		Width(50).
		Align(lipgloss.Left)

	var menuContent strings.Builder
	menuItems := []struct {
		icon string
		text string
	}{
		{"🔍", "Check Input"},
		{"📦", "Batch Processing"},
		{"⚙️ ", "Settings"},
		{"📖", "About"},
		{"🚪", "Exit"},
	}

	for i, item := range menuItems {
		if i == m.menuChoice {
			menuContent.WriteString(selectedStyle.Render(fmt.Sprintf(" %s %s ", item.icon, item.text)))
		} else {
			menuContent.WriteString(normalStyle.Render(fmt.Sprintf("  %s %s ", item.icon, item.text)))
		}
		menuContent.WriteString("\n")
	}

	menu := menuPanel.Render(menuContent.String())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, menu))

	help := helpStyle.Render("↑/↓: Navigate  •  Enter: Select  •  Q: Quit")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func (m model) viewCheck() string {
	var s strings.Builder
	s.WriteString("\n\n")

	title := sectionHeaderStyle.Render("Check Input")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, title))
	s.WriteString("\n\n")

	inputPanel := panelStyle.Width(70).Render(m.input.View())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, inputPanel))

	if m.checking {
		loadingMsg := "Analyzing"
		if m.enableLLM && m.llmProvider != "none" {
			loadingMsg = fmt.Sprintf("🔄 Analyzing with %s...", capitalizeProviderName(m.llmProvider))
		} else {
			loadingMsg = "🔄 Analyzing..."
		}
		loading := lipgloss.NewStyle().Foreground(warningColor).Render(loadingMsg)
		s.WriteString("\n\n")
		s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, loading))
	} else if m.enableLLM && m.llmProvider != "none" {
		modeNames := []string{"Always", "Conditional", "Fallback"}
		llmStatus := fmt.Sprintf("LLM: %s (%s mode)", capitalizeProviderName(m.llmProvider), modeNames[m.llmMode])
		llmInfo := lipgloss.NewStyle().Foreground(secondaryColor).Render(llmStatus)
		s.WriteString("\n")
		s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, llmInfo))
	}

	help := helpStyle.Render("Enter: Analyze  •  Esc: Back")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func (m model) viewResults() string {
	var s strings.Builder
	s.WriteString("\n\n")

	title := sectionHeaderStyle.Render("Results")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, title))
	s.WriteString("\n\n")

	inputDisplay := m.lastInput
	if len(inputDisplay) > 80 {
		inputDisplay = inputDisplay[:80] + "..."
	}
	inputBox := panelStyle.Width(70).Render("Input: \"" + inputDisplay + "\"")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, inputBox))
	s.WriteString("\n")

	var statusPanel string
	if m.result.Safe {
		statusPanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(safeColor).
			Padding(1, 3).
			Width(70).
			Render(safeStyle.Render("✓ SAFE") + "\n\nNo injection detected")
	} else {
		severity := "Low Risk"
		if m.result.RiskScore >= 0.9 {
			severity = "High Risk"
		} else if m.result.RiskScore >= 0.7 {
			severity = "Medium Risk"
		}

		statusPanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(dangerColor).
			Padding(1, 3).
			Width(70).
			Render(unsafeStyle.Render("⚠ UNSAFE") + "\n\n" + severity)
	}
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, statusPanel))
	s.WriteString("\n")

	var metricsContent strings.Builder
	metricsContent.WriteString(fmt.Sprintf("Risk: %.2f  •  Confidence: %.2f\n\n", m.result.RiskScore, m.result.Confidence))

	barWidth := 50
	filled := int(m.result.RiskScore * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	barColor := safeColor
	if m.result.RiskScore >= 0.9 {
		barColor = dangerColor
	} else if m.result.RiskScore >= 0.7 {
		barColor = warningColor
	}
	metricsContent.WriteString(lipgloss.NewStyle().Foreground(barColor).Render(bar))

	llmUsed := false
	var llmPattern *detector.DetectedPatterns
	for i := range m.result.DetectedPatterns {
		if strings.HasPrefix(m.result.DetectedPatterns[i].Type, "llm_") {
			llmUsed = true
			llmPattern = &m.result.DetectedPatterns[i]
			break
		}
	}

	if len(m.result.DetectedPatterns) > 0 {
		metricsContent.WriteString("\n\nDetected:\n")
		for _, pattern := range m.result.DetectedPatterns {
			if !strings.HasPrefix(pattern.Type, "llm_") {
				metricsContent.WriteString(fmt.Sprintf("  • %s (%.2f)\n", pattern.Type, pattern.Score))
			}
		}
	}

	if llmUsed && llmPattern != nil {
		metricsContent.WriteString("\n")
		llmVerdict := lipgloss.NewStyle().Foreground(secondaryColor).Render("LLM Judge:")
		metricsContent.WriteString(llmVerdict + "\n")

		if llmPattern.Type == "llm_error" {
			metricsContent.WriteString(lipgloss.NewStyle().Foreground(warningColor).Render("  Error: "))
			if len(llmPattern.Matches) > 0 {
				metricsContent.WriteString(llmPattern.Matches[0] + "\n")
			}
		} else {
			metricsContent.WriteString(fmt.Sprintf("  • %s (%.2f)\n", strings.TrimPrefix(llmPattern.Type, "llm_"), llmPattern.Score))
			if len(llmPattern.Matches) > 1 && llmPattern.Matches[1] != "" {
				reasoning := llmPattern.Matches[1]
				if len(reasoning) > 100 {
					reasoning = reasoning[:100] + "..."
				}
				metricsContent.WriteString(lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("    \"%s\"\n", reasoning)))
			}
		}
	} else if m.enableLLM && m.llmProvider != "none" {
		metricsContent.WriteString("\n")
		modeNames := []string{"always", "when uncertain", "when safe"}
		llmSkipped := lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("LLM not consulted (runs %s)", modeNames[m.llmMode]))
		metricsContent.WriteString(llmSkipped + "\n")
	}

	metricsPanel := panelStyle.Width(70).Render(metricsContent.String())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, metricsPanel))

	help := helpStyle.Render("Enter: Check Another  •  Esc: Menu")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func (m model) viewSettings() string {
	var s strings.Builder
	s.WriteString("\n\n")

	title := sectionHeaderStyle.Render("Settings")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, title))
	s.WriteString("\n\n")

	var content strings.Builder

	toggle := func(enabled bool) string {
		if enabled {
			return safeStyle.Render("ON ")
		}
		return lipgloss.NewStyle().Foreground(mutedColor).Render("OFF")
	}

	selector := func(idx int, text string) string {
		if idx == m.settingsChoice {
			return lipgloss.NewStyle().Foreground(primaryColor).Render("> ") + text
		}
		return "  " + text
	}

	// 0: Threshold
	thresholdLine := fmt.Sprintf("Threshold: %.2f  (←/→ to adjust)", m.threshold)
	content.WriteString(selector(0, thresholdLine) + "\n\n")

	content.WriteString("Pattern Detectors:\n")
	content.WriteString(selector(1, fmt.Sprintf("[1] Role Injection       %s", toggle(m.enableRoleInj))) + "\n")
	content.WriteString(selector(2, fmt.Sprintf("[2] Prompt Leak          %s", toggle(m.enablePromptLeak))) + "\n")
	content.WriteString(selector(3, fmt.Sprintf("[3] Instruction Override %s", toggle(m.enableInstOverride))) + "\n")
	content.WriteString(selector(4, fmt.Sprintf("[4] Obfuscation          %s", toggle(m.enableObfuscation))) + "\n\n")

	content.WriteString("Statistical Detectors:\n")
	content.WriteString(selector(5, fmt.Sprintf("[5] Entropy              %s", toggle(m.enableEntropy))) + "\n")
	content.WriteString(selector(6, fmt.Sprintf("[6] Perplexity           %s", toggle(m.enablePerp))) + "\n")
	content.WriteString(selector(7, fmt.Sprintf("[7] Token Anomaly        %s", toggle(m.enableToken))) + "\n\n")

	content.WriteString("LLM Judge:\n")
	content.WriteString(selector(8, fmt.Sprintf("[8] Enable               %s", toggle(m.enableLLM))) + "\n")

	modeNames := []string{"Always", "Conditional", "Fallback"}
	modeName := modeNames[m.llmMode]
	content.WriteString(selector(9, fmt.Sprintf("[9] Mode                 %s", modeName)) + "\n")

	providerDisplay := capitalizeProviderName(m.llmProvider)
	if m.llmProvider == "none" {
		providerDisplay = lipgloss.NewStyle().Foreground(mutedColor).Render(providerDisplay)
	}
	content.WriteString(selector(10, fmt.Sprintf("[0] Provider             %s", providerDisplay)) + "\n")

	if len(m.availableProviders) > 1 {
		capitalizedProviders := make([]string, len(m.availableProviders))
		for i, p := range m.availableProviders {
			capitalizedProviders[i] = capitalizeProviderName(p)
		}
		providers := strings.Join(capitalizedProviders, ", ")
		content.WriteString(lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("      Available: %s\n", providers)))
	}

	panel := panelStyle.Width(70).Render(content.String())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, panel))

	help := helpStyle.Render("↑/↓: Navigate  •  Enter/Space: Toggle  •  ←/→: Adjust  •  0-9: Quick Select  •  Esc: Back")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func (m model) viewAbout() string {
	var s strings.Builder
	s.WriteString("\n\n")

	title := sectionHeaderStyle.Render("About")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, title))
	s.WriteString("\n\n")

	content := fmt.Sprintf(`go-promptguard

Prompt injection detection library for Go

Version: %s
Repository: github.com/mdombrov-33/go-promptguard

Detectors:
  • Role Injection
  • Prompt Leak
  • Instruction Override
  • Obfuscation
  • Entropy Analysis
  • Perplexity Analysis
  • Token Anomaly
  • LLM Judge (optional)
`, version)

	panel := panelStyle.Width(70).Render(content)
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, panel))

	help := helpStyle.Render("Esc: Back")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func (m model) viewBatch() string {
	var s strings.Builder
	s.WriteString("\n\n")

	title := sectionHeaderStyle.Render("Batch Processing")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, title))
	s.WriteString("\n\n")

	var content strings.Builder
	content.WriteString("File path (TXT or CSV):\n\n")
	content.WriteString(m.fileInput.View())

	if m.batchProcessing {
		content.WriteString("\n\n")
		content.WriteString(lipgloss.NewStyle().Foreground(warningColor).Render("⏳ Processing..."))
	} else if m.batchError != nil {
		content.WriteString("\n\n")
		errorMsg := fmt.Sprintf("❌ Error: %s", m.batchError.Error())
		content.WriteString(lipgloss.NewStyle().Foreground(dangerColor).Render(errorMsg))
	} else {
		content.WriteString("\n\nSupported: TXT (one per line), CSV (first column)")
	}

	panel := panelStyle.Width(70).Render(content.String())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, panel))

	help := helpStyle.Render("Enter: Process  •  Esc: Back")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func (m model) viewBatchResults() string {
	var s strings.Builder
	s.WriteString("\n\n")

	title := sectionHeaderStyle.Render("Batch Results")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, title))
	s.WriteString("\n\n")

	if m.batchSummary == nil {
		return s.String()
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("Total: %d  •  Safe: %d  •  Unsafe: %d\n\n",
		m.batchSummary.Total,
		m.batchSummary.Safe,
		m.batchSummary.Unsafe))

	if m.batchSummary.Unsafe > 0 {
		content.WriteString(fmt.Sprintf("High: %d  •  Medium: %d  •  Low: %d\n\n",
			m.batchSummary.HighRisk,
			m.batchSummary.MediumRisk,
			m.batchSummary.LowRisk))
	}

	content.WriteString(fmt.Sprintf("Duration: %s\n\n", m.batchSummary.Duration.Round(time.Millisecond)))
	content.WriteString("Export (saved to batch_results/):\n")
	content.WriteString("  [S] Save as CSV\n")
	content.WriteString("  [J] Save as JSON")

	panel := panelStyle.Width(70).Render(content.String())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, panel))

	help := helpStyle.Render("S/J: Export  •  Enter: New Batch  •  Esc: Back")
	s.WriteString("\n\n")
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, help))

	return s.String()
}

func capitalizeProviderName(p string) string {
	switch p {
	case "openai":
		return "OpenAI"
	case "openrouter":
		return "OpenRouter"
	case "anthropic":
		return "Anthropic"
	case "ollama":
		return "Ollama"
	case "none":
		return "None"
	default:
		return p
	}
}

func runInteractive() error {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
