package main

import (
	"context"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mdombrov-33/go-promptguard/detector"
)

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
			if m.settingsChoice < 14 { // 0-14 = 15 settings total
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
		m.enableNorm = !m.enableNorm
		return true
	case 6:
		// Toggle normalization mode
		if m.normMode == detector.ModeBalanced {
			m.normMode = detector.ModeAggressive
		} else {
			m.normMode = detector.ModeBalanced
		}
		return true
	case 7:
		m.enableDelim = !m.enableDelim
		return true
	case 8:
		// Toggle delimiter mode
		if m.delimMode == detector.ModeBalanced {
			m.delimMode = detector.ModeAggressive
		} else {
			m.delimMode = detector.ModeBalanced
		}
		return true
	case 9:
		m.enableEntropy = !m.enableEntropy
		return true
	case 10:
		m.enablePerp = !m.enablePerp
		return true
	case 11:
		m.enableToken = !m.enableToken
		return true
	case 12:
		m.enableLLM = !m.enableLLM
		return true
	case 13:
		m.llmMode = (m.llmMode + 1) % 3
		return true
	case 14:
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
