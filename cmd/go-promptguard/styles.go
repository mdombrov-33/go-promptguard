package main

import "github.com/charmbracelet/lipgloss"

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
