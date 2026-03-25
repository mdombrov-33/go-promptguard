package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

func runInteractive() error {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	_, err := p.Run()
	if err != nil {
		return fmt.Errorf("interactive mode error: %w", err)
	}
	return nil
}
