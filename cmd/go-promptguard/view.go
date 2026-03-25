package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mdombrov-33/go-promptguard/detector"
)

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

func (m model) getPanelWidth() int {
	// Adaptive width based on terminal width
	// Min: 70, Max: 120
	width := min(m.width-10, 120)
	return max(width, 70)
}

func (m model) viewMenu() string {
	var s strings.Builder

	// Add vertical spacing based on terminal height
	topPadding := max(1, (m.height-30)/2)
	for i := 0; i < topPadding; i++ {
		s.WriteString("\n")
	}

	header := titleStyle.Render("go-promptguard")
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
		{"🔧", "Settings"},
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

	inputPanel := panelStyle.Width(m.getPanelWidth()).Render(m.input.View())
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
	inputBox := panelStyle.Width(m.getPanelWidth()).Render("Input: \"" + inputDisplay + "\"")
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
	var llmPattern *detector.DetectedPattern
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

	metricsPanel := panelStyle.Width(m.getPanelWidth()).Render(metricsContent.String())
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

	modeDisplay := func(mode detector.DetectionMode) string {
		if mode == detector.ModeAggressive {
			return "Aggressive"
		}
		return "Balanced"
	}

	content.WriteString("Pattern Detectors:\n")
	content.WriteString(selector(1, fmt.Sprintf("  Role Injection       %s", toggle(m.enableRoleInj))) + "\n")
	content.WriteString(selector(2, fmt.Sprintf("  Prompt Leak          %s", toggle(m.enablePromptLeak))) + "\n")
	content.WriteString(selector(3, fmt.Sprintf("  Instruction Override %s", toggle(m.enableInstOverride))) + "\n")
	content.WriteString(selector(4, fmt.Sprintf("  Obfuscation          %s", toggle(m.enableObfuscation))) + "\n")
	content.WriteString(selector(5, fmt.Sprintf("  Normalization        %s", toggle(m.enableNorm))) + "\n")
	content.WriteString(selector(6, fmt.Sprintf("    Mode               %s", modeDisplay(m.normMode))) + "\n")
	content.WriteString(selector(7, fmt.Sprintf("  Delimiter            %s", toggle(m.enableDelim))) + "\n")
	content.WriteString(selector(8, fmt.Sprintf("    Mode               %s", modeDisplay(m.delimMode))) + "\n\n")

	content.WriteString("Statistical Detectors:\n")
	content.WriteString(selector(9, fmt.Sprintf("  Entropy              %s", toggle(m.enableEntropy))) + "\n")
	content.WriteString(selector(10, fmt.Sprintf("  Perplexity           %s", toggle(m.enablePerp))) + "\n")
	content.WriteString(selector(11, fmt.Sprintf("  Token Anomaly        %s", toggle(m.enableToken))) + "\n\n")

	content.WriteString("LLM Judge:\n")
	content.WriteString(selector(12, fmt.Sprintf("  Enable               %s", toggle(m.enableLLM))) + "\n")

	modeNames := []string{"Always", "Conditional", "Fallback"}
	modeName := modeNames[m.llmMode]
	content.WriteString(selector(13, fmt.Sprintf("  Mode                 %s", modeName)) + "\n")

	providerDisplay := capitalizeProviderName(m.llmProvider)
	if m.llmProvider == "none" {
		providerDisplay = lipgloss.NewStyle().Foreground(mutedColor).Render(providerDisplay)
	}
	content.WriteString(selector(14, fmt.Sprintf("  Provider             %s", providerDisplay)) + "\n")

	content.WriteString("\n")

	// Show active model for current provider
	if m.llmProvider != "none" {
		var modelName string
		switch m.llmProvider {
		case "openai":
			modelName = os.Getenv("OPENAI_MODEL")
			if modelName == "" {
				modelName = "gpt-5 (default)"
			}
		case "openrouter":
			modelName = os.Getenv("OPENROUTER_MODEL")
			if modelName == "" {
				modelName = "anthropic/claude-sonnet-4.5 (default)"
			}
		case "ollama":
			modelName = os.Getenv("OLLAMA_MODEL")
			if modelName == "" {
				modelName = "llama3.1:8b (default)"
			}
		}
		styledModel := lipgloss.NewStyle().Foreground(mutedColor).Render(modelName)
		content.WriteString(fmt.Sprintf("  Model: %s\n", styledModel))
	}

	if len(m.availableProviders) > 1 {
		capitalizedProviders := make([]string, len(m.availableProviders))
		for i, p := range m.availableProviders {
			capitalizedProviders[i] = capitalizeProviderName(p)
		}
		providers := strings.Join(capitalizedProviders, ", ")
		styledProviders := lipgloss.NewStyle().Foreground(mutedColor).Render(providers)
		content.WriteString(fmt.Sprintf("  Available: %s\n", styledProviders))
	}

	panel := panelStyle.Width(m.getPanelWidth()).Render(content.String())
	s.WriteString(lipgloss.Place(m.width, 0, lipgloss.Center, lipgloss.Top, panel))

	help := helpStyle.Render("↑/↓: Navigate  •  Enter/Space: Toggle  •  ←/→: Adjust Threshold  •  Esc: Back")
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
  • Normalization
  • Delimiter
  • Entropy Analysis
  • Perplexity Analysis
  • Token Anomaly
  • LLM Judge (optional)
`, version)

	panel := panelStyle.Width(m.getPanelWidth()).Render(content)
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

	panel := panelStyle.Width(m.getPanelWidth()).Render(content.String())
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

	panel := panelStyle.Width(m.getPanelWidth()).Render(content.String())
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
	case "ollama":
		return "Ollama"
	case "none":
		return "None"
	default:
		return p
	}
}
