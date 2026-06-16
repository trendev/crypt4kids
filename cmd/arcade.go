package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	defaultArcadeWidth  = 100
	defaultArcadeHeight = 32
	minArcadeWidth      = 74
	maxArcadeWidth      = 116
)

type arcadeAlgorithm struct {
	key   string
	title string
	tag   string
}

var arcadeAlgorithms = []arcadeAlgorithm{
	{key: "rot13", title: "ROT13", tag: "SHIFT 13"},
	{key: "atbash", title: "ATBASH", tag: "MIRROR"},
	{key: "atbashrot13", title: "ATBASH+ROT13", tag: "COMBO A"},
	{key: "rot13atbash", title: "ROT13+ATBASH", tag: "COMBO B"},
}

type arcadeMode int

const (
	arcadeModeCommand arcadeMode = iota
	arcadeModeTyping
)

type arcadeTick time.Time

type cyberpunkArcadeModel struct {
	algorithm string
	input     []rune
	output    string
	hasOutput bool
	status    string
	mode      arcadeMode
	cursor    int
	frame     int
	width     int
	height    int
}

type cyberpunkStyles struct {
	screen   lipgloss.Style
	title    lipgloss.Style
	subtitle lipgloss.Style
	panel    lipgloss.Style
	active   lipgloss.Style
	button   lipgloss.Style
	status   lipgloss.Style
	dim      lipgloss.Style
	cyan     lipgloss.Style
	magenta  lipgloss.Style
	yellow   lipgloss.Style
	green    lipgloss.Style
	red      lipgloss.Style
}

func runArcade(stdin io.Reader, stdout, stderr io.Writer, initialAlg string) int {
	program := tea.NewProgram(
		newCyberpunkArcadeModel(initialAlg),
		tea.WithInput(stdin),
		tea.WithOutput(stdout),
		tea.WithFPS(30),
	)

	if _, err := program.Run(); err != nil {
		fmt.Fprintf(stderr, "error running arcade interface: %v\n", err)
		return 1
	}

	return 0
}

func newCyberpunkArcadeModel(initialAlg string) cyberpunkArcadeModel {
	return cyberpunkArcadeModel{
		algorithm: normalizeAlgorithm(initialAlg),
		status:    "NEON LINK READY",
		width:     defaultArcadeWidth,
		height:    defaultArcadeHeight,
	}
}

func (m cyberpunkArcadeModel) Init() tea.Cmd {
	return arcadePulse()
}

func (m cyberpunkArcadeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case arcadeTick:
		m.frame++
		return m, arcadePulse()
	case tea.PasteMsg:
		if m.mode == arcadeModeTyping {
			m.insertText(msg.Content)
			m.status = "PASTE BUFFER CAPTURED"
		}
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m cyberpunkArcadeModel) View() tea.View {
	view := tea.NewView(m.render())
	view.AltScreen = true
	view.WindowTitle = "crypt4kids // cyber arcade"
	return view
}

func (m cyberpunkArcadeModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.mode == arcadeModeTyping {
		return m.handleTypingKey(msg)
	}

	switch msg.String() {
	case "ctrl+c", "q":
		m.status = "SIGNAL CLOSED"
		return m, tea.Quit
	case "1":
		m.setAlgorithm("rot13")
	case "2":
		m.setAlgorithm("atbash")
	case "3":
		m.setAlgorithm("atbashrot13")
	case "4":
		m.setAlgorithm("rot13atbash")
	case "t", "i":
		m.mode = arcadeModeTyping
		m.cursor = len(m.input)
		m.status = "TYPE MODE: ENTER TEXT, PRESS ENTER TO ARM"
	case "e", "enter":
		m.encrypt()
	case "c":
		m.clear()
	default:
		m.status = "UNKNOWN CONTROL: USE 1-4, T, E, C, OR Q"
	}

	return m, nil
}

func (m cyberpunkArcadeModel) handleTypingKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		m.mode = arcadeModeCommand
		if len(m.input) == 0 {
			m.status = "INPUT BUFFER EMPTY"
		} else {
			m.status = "INPUT ARMED: PRESS E TO ENCRYPT"
		}
	case "esc":
		m.mode = arcadeModeCommand
		m.status = "TYPE MODE CANCELLED"
	case "left":
		if m.cursor > 0 {
			m.cursor--
		}
	case "right":
		if m.cursor < len(m.input) {
			m.cursor++
		}
	case "home", "ctrl+a":
		m.cursor = 0
	case "end", "ctrl+e":
		m.cursor = len(m.input)
	case "backspace", "ctrl+h":
		if m.cursor > 0 {
			m.input = append(m.input[:m.cursor-1], m.input[m.cursor:]...)
			m.cursor--
			m.hasOutput = false
			m.output = ""
		}
	case "delete":
		if m.cursor < len(m.input) {
			m.input = append(m.input[:m.cursor], m.input[m.cursor+1:]...)
			m.hasOutput = false
			m.output = ""
		}
	default:
		if text := msg.Key().Text; text != "" {
			m.insertText(text)
			m.status = "CAPTURING PLAINTEXT"
		}
	}

	return m, nil
}

func (m *cyberpunkArcadeModel) setAlgorithm(alg string) {
	m.algorithm = normalizeAlgorithm(alg)
	m.output = ""
	m.hasOutput = false
	m.status = "CARTRIDGE LOADED: " + algorithmDisplayName(m.algorithm)
}

func (m *cyberpunkArcadeModel) insertText(text string) {
	runes := []rune(text)
	if len(runes) == 0 {
		return
	}

	m.input = append(m.input[:m.cursor], append(runes, m.input[m.cursor:]...)...)
	m.cursor += len(runes)
	m.output = ""
	m.hasOutput = false
}

func (m *cyberpunkArcadeModel) encrypt() {
	if len(m.input) == 0 {
		m.output = ""
		m.hasOutput = false
		m.status = "NO PLAINTEXT IN BUFFER"
		return
	}

	m.output = encodeString(m.algorithm, string(m.input))
	m.hasOutput = true
	m.status = "CIPHER BURST COMPLETE"
}

func (m *cyberpunkArcadeModel) clear() {
	m.input = nil
	m.output = ""
	m.hasOutput = false
	m.cursor = 0
	m.mode = arcadeModeCommand
	m.status = "BUFFER PURGED"
}

func arcadePulse() tea.Cmd {
	return tea.Tick(400*time.Millisecond, func(t time.Time) tea.Msg {
		return arcadeTick(t)
	})
}

func (m cyberpunkArcadeModel) render() string {
	styles := newCyberpunkStyles()
	width := clamp(m.width-4, minArcadeWidth, maxArcadeWidth)
	if width <= 0 {
		width = defaultArcadeWidth
	}

	bodyWidth := width - styles.screen.GetHorizontalFrameSize()
	if bodyWidth < minArcadeWidth-4 {
		bodyWidth = minArcadeWidth - 4
	}

	sections := []string{
		renderArcadeHeader(styles, bodyWidth),
		renderNeonCity(styles, bodyWidth, m.frame),
		renderAlgorithmDeck(styles, bodyWidth, m.algorithm),
		renderCipherDeck(styles, bodyWidth, m),
		renderControlDeck(styles, bodyWidth, m),
	}

	return styles.screen.Width(width).Render(strings.Join(sections, "\n"))
}

func newCyberpunkStyles() cyberpunkStyles {
	black := lipgloss.Color("#05000D")
	cyan := lipgloss.Color("#00F5FF")
	magenta := lipgloss.Color("#FF00A8")
	violet := lipgloss.Color("#7A18FF")
	yellow := lipgloss.Color("#F8EF00")
	green := lipgloss.Color("#22FF88")
	red := lipgloss.Color("#FF3B5C")
	white := lipgloss.Color("#F6F7FF")

	return cyberpunkStyles{
		screen: lipgloss.NewStyle().
			Background(black).
			Foreground(white).
			Padding(1, 2).
			Border(lipgloss.DoubleBorder()).
			BorderForegroundBlend(cyan, magenta),
		title: lipgloss.NewStyle().
			Foreground(cyan).
			Background(lipgloss.Color("#16001F")).
			Bold(true).
			Padding(0, 1),
		subtitle: lipgloss.NewStyle().
			Foreground(yellow).
			Bold(true),
		panel: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(violet).
			Padding(0, 1),
		active: lipgloss.NewStyle().
			Foreground(black).
			Background(magenta).
			Bold(true).
			Padding(0, 1),
		button: lipgloss.NewStyle().
			Foreground(cyan).
			Border(lipgloss.NormalBorder()).
			BorderForeground(cyan).
			Padding(0, 1),
		status: lipgloss.NewStyle().
			Foreground(green).
			Bold(true),
		dim: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#73738F")),
		cyan: lipgloss.NewStyle().
			Foreground(cyan).
			Bold(true),
		magenta: lipgloss.NewStyle().
			Foreground(magenta).
			Bold(true),
		yellow: lipgloss.NewStyle().
			Foreground(yellow).
			Bold(true),
		green: lipgloss.NewStyle().
			Foreground(green).
			Bold(true),
		red: lipgloss.NewStyle().
			Foreground(red).
			Bold(true),
	}
}

func renderArcadeHeader(styles cyberpunkStyles, width int) string {
	title := styles.title.Width(width).Align(lipgloss.Center).Render("CRYPT4KIDS // CYBER ARCADE")
	subtitle := styles.subtitle.Width(width).Align(lipgloss.Center).Render("NEON CIPHER CABINET - 8 BIT TERMINAL MODE")
	return lipgloss.JoinVertical(lipgloss.Left, title, subtitle)
}

func renderNeonCity(styles cyberpunkStyles, width, frame int) string {
	city := []string{
		"          /\\                         /\\",
		"   ______/##\\______      _________/##\\______",
		"  | []  []  []  [] |____| []  []  []  [] |",
		"  | []  NEON CITY  |####|  CIPHER  GRID  |",
		"  |____[][][][]____|____|____[][][][]____|",
	}

	for i, line := range city {
		switch i % 3 {
		case 0:
			city[i] = styles.cyan.Render(line)
		case 1:
			city[i] = styles.magenta.Render(line)
		default:
			city[i] = styles.yellow.Render(line)
		}
	}

	rain := styles.green.Render(dataRain(width, frame))
	panel := lipgloss.JoinVertical(lipgloss.Center, append(city, rain)...)
	return styles.panel.Width(width).Align(lipgloss.Center).Render(panel)
}

func renderAlgorithmDeck(styles cyberpunkStyles, width int, activeAlg string) string {
	buttonWidth := max(13, (width-8)/4)
	buttons := make([]string, 0, len(arcadeAlgorithms))
	for i, alg := range arcadeAlgorithms {
		label := fmt.Sprintf("[%d] %s", i+1, alg.title)
		style := styles.button.Width(buttonWidth).Align(lipgloss.Center)
		if alg.key == activeAlg {
			style = styles.active.Width(buttonWidth).Align(lipgloss.Center)
			label = "> " + label + " <"
		}
		buttons = append(buttons, style.Render(label))
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, buttons...)
	caption := styles.dim.Render("algorithm cartridges: rot13 / atbash / combo routes")
	return styles.panel.Width(width).Render(lipgloss.JoinVertical(lipgloss.Left, caption, row))
}

func renderCipherDeck(styles cyberpunkStyles, width int, m cyberpunkArcadeModel) string {
	panelWidth := max(28, (width-4)/2)
	input := string(m.input)
	if m.mode == arcadeModeTyping {
		input = renderInputCursor(input, m.cursor)
	}
	input = emptyValue(input, "<empty input buffer>")
	output := "<waiting for encryption>"
	if m.hasOutput {
		output = emptyValue(m.output, "<empty cipher output>")
	}

	left := styles.panel.
		Width(panelWidth).
		BorderForeground(lipgloss.Color("#00F5FF")).
		Render(lipgloss.JoinVertical(
			lipgloss.Left,
			styles.cyan.Render("PLAINTEXT TERMINAL"),
			wrapRunes(input, panelWidth-4),
		))
	right := styles.panel.
		Width(panelWidth).
		BorderForeground(lipgloss.Color("#FF00A8")).
		Render(lipgloss.JoinVertical(
			lipgloss.Left,
			styles.magenta.Render("CIPHER OUTPUT"),
			wrapRunes(output, panelWidth-4),
		))

	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
}

func renderControlDeck(styles cyberpunkStyles, width int, m cyberpunkArcadeModel) string {
	mode := "COMMAND"
	modeStyle := styles.cyan
	if m.mode == arcadeModeTyping {
		mode = "TYPE"
		modeStyle = styles.yellow
	}

	status := lipgloss.JoinHorizontal(
		lipgloss.Top,
		modeStyle.Render("MODE: "+mode),
		"  ",
		styles.status.Render("STATUS: "+m.status),
		"  ",
		styles.green.Render("ACTIVE: "+algorithmDisplayName(m.algorithm)),
	)
	controls := "[1-4] cartridge  [T] text  [E/ENTER] encrypt  [C] clear  [Q] quit"
	if m.mode == arcadeModeTyping {
		controls = "typing: text keys insert  [ENTER] arm  [ESC] cancel  arrows move cursor"
	}

	return styles.panel.Width(width).Render(lipgloss.JoinVertical(
		lipgloss.Left,
		status,
		styles.dim.Render(controls),
	))
}

func renderInputCursor(text string, cursor int) string {
	runes := []rune(text)
	if cursor < 0 {
		cursor = 0
	}
	if cursor > len(runes) {
		cursor = len(runes)
	}

	runes = append(runes[:cursor], append([]rune{'█'}, runes[cursor:]...)...)
	return string(runes)
}

func dataRain(width, frame int) string {
	pattern := "0101 1110 0011 1001 "
	if width < len(pattern) {
		width = len(pattern)
	}

	repeated := strings.Repeat(pattern, width/len(pattern)+2)
	offset := frame % len(pattern)
	return repeated[offset : offset+width]
}

func wrapRunes(text string, width int) string {
	if width < 8 {
		width = 8
	}
	if text == "" {
		return ""
	}

	var lines []string
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\t", "    "), "\n") {
		runes := []rune(raw)
		if len(runes) == 0 {
			lines = append(lines, "")
			continue
		}
		for len(runes) > width {
			lines = append(lines, string(runes[:width]))
			runes = runes[width:]
		}
		lines = append(lines, string(runes))
	}

	return strings.Join(lines, "\n")
}

func emptyValue(value, empty string) string {
	if value == "" {
		return empty
	}

	return value
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}

	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}
