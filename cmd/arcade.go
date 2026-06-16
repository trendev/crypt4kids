package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	arcadeWidth      = 78
	arcadeInnerWidth = arcadeWidth - 4
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

type arcadeState struct {
	algorithm string
	input     string
	output    string
	hasOutput bool
	status    string
}

type arcadeAction int

const (
	arcadeContinue arcadeAction = iota
	arcadeReadText
	arcadeQuit
)

type arcadeTheme struct {
	clear string
	reset string
	title string
	live  string
}

func runArcade(stdin io.Reader, stdout, stderr io.Writer, initialAlg string, ansi bool) int {
	reader := bufio.NewReader(stdin)
	state := newArcadeState(initialAlg)

	for {
		renderArcade(stdout, state, ansi)
		fmt.Fprint(stdout, "COMMAND> ")

		command, err := readArcadeLine(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(stdout, "\nGAME OVER")
				return 0
			}
			fmt.Fprintf(stderr, "error reading arcade command: %v\n", err)
			return 1
		}

		switch handleArcadeCommand(&state, command) {
		case arcadeReadText:
			fmt.Fprint(stdout, "TEXT> ")
			text, err := readArcadeLine(reader)
			if err != nil {
				if errors.Is(err, io.EOF) {
					fmt.Fprintln(stdout, "\nGAME OVER")
					return 0
				}
				fmt.Fprintf(stderr, "error reading arcade text: %v\n", err)
				return 1
			}
			setArcadeText(&state, text)
		case arcadeQuit:
			fmt.Fprintln(stdout, "GAME OVER")
			return 0
		}
	}
}

func newArcadeState(initialAlg string) arcadeState {
	return arcadeState{
		algorithm: normalizeAlgorithm(initialAlg),
		status:    "READY",
	}
}

func handleArcadeCommand(state *arcadeState, command string) arcadeAction {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "":
		state.status = "INSERT COMMAND"
	case "1", "rot13":
		setArcadeAlgorithm(state, "rot13")
	case "2", "atbash":
		setArcadeAlgorithm(state, "atbash")
	case "3", "atbashrot13", "atbash+rot13":
		setArcadeAlgorithm(state, "atbashrot13")
	case "4", "rot13atbash", "rot13+atbash":
		setArcadeAlgorithm(state, "rot13atbash")
	case "t", "text":
		state.status = "TYPE YOUR SECRET MESSAGE"
		return arcadeReadText
	case "e", "encrypt":
		if state.input == "" {
			state.output = ""
			state.hasOutput = false
			state.status = "NO TEXT LOADED"
			return arcadeContinue
		}
		state.output = encodeString(state.algorithm, state.input)
		state.hasOutput = true
		state.status = "ENCRYPT COMPLETE"
	case "c", "clear":
		state.input = ""
		state.output = ""
		state.hasOutput = false
		state.status = "MEMORY CLEARED"
	case "q", "quit", "exit":
		return arcadeQuit
	default:
		state.status = "UNKNOWN COMMAND"
	}

	return arcadeContinue
}

func setArcadeAlgorithm(state *arcadeState, alg string) {
	state.algorithm = normalizeAlgorithm(alg)
	state.output = ""
	state.hasOutput = false
	state.status = "PLAYER SELECTED " + algorithmDisplayName(state.algorithm)
}

func setArcadeText(state *arcadeState, text string) {
	state.input = text
	state.output = ""
	state.hasOutput = false
	if text == "" {
		state.status = "TEXT CLEARED"
		return
	}
	state.status = "TEXT LOADED"
}

func readArcadeLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}

func renderArcade(w io.Writer, state arcadeState, ansi bool) {
	theme := newArcadeTheme(ansi)
	if theme.clear != "" {
		fmt.Fprint(w, theme.clear)
	}

	arcadeBorder(w)
	fmt.Fprint(w, theme.title)
	arcadeLine(w, "       C R Y P T 4 K I D S  //  C I P H E R  A R C A D E")
	fmt.Fprint(w, theme.reset)
	arcadeLine(w, "       8-BIT ENCRYPTION STATION")
	arcadeBorder(w)
	arcadeLine(w, "PICK YOUR ALGORITHM")
	for i, alg := range arcadeAlgorithms {
		marker := " "
		if alg.key == state.algorithm {
			marker = ">"
		}
		arcadeLine(w, fmt.Sprintf("%s [%d] %-13s %s", marker, i+1, alg.title, alg.tag))
	}
	arcadeBorder(w)
	fmt.Fprint(w, theme.live)
	arcadeLine(w, "ACTIVE ALGORITHM: "+algorithmDisplayName(state.algorithm))
	fmt.Fprint(w, theme.reset)
	arcadeLine(w, "INPUT : "+arcadeDisplayText(state.input, "<empty>"))
	if state.hasOutput {
		arcadeLine(w, "OUTPUT: "+arcadeDisplayText(state.output, "<empty>"))
	} else {
		arcadeLine(w, "OUTPUT: <waiting for encrypt>")
	}
	arcadeLine(w, "STATUS: "+state.status)
	arcadeBorder(w)
	arcadeLine(w, "[1-4] ALGORITHM   [T] TEXT   [E] ENCRYPT   [C] CLEAR   [Q] QUIT")
	arcadeBorder(w)
}

func newArcadeTheme(ansi bool) arcadeTheme {
	if !ansi {
		return arcadeTheme{}
	}

	return arcadeTheme{
		clear: "\x1b[2J\x1b[H",
		reset: "\x1b[0m",
		title: "\x1b[96;1m",
		live:  "\x1b[92;1m",
	}
}

func arcadeDisplayText(text, empty string) string {
	if text == "" {
		return empty
	}

	return text
}

func arcadeBorder(w io.Writer) {
	fmt.Fprintf(w, "+%s+\n", strings.Repeat("-", arcadeWidth-2))
}

func arcadeLine(w io.Writer, text string) {
	lines := wrapArcadeText(text, arcadeInnerWidth)
	for _, line := range lines {
		fmt.Fprintf(w, "| %s |\n", padArcadeText(line, arcadeInnerWidth))
	}
}

func wrapArcadeText(text string, width int) []string {
	if text == "" {
		return []string{""}
	}

	var lines []string
	for _, rawLine := range strings.Split(strings.ReplaceAll(text, "\t", "    "), "\n") {
		runes := []rune(rawLine)
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

	return lines
}

func padArcadeText(text string, width int) string {
	runes := []rune(text)
	if len(runes) >= width {
		return string(runes[:width])
	}

	return text + strings.Repeat(" ", width-len(runes))
}
