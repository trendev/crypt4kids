package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

func TestRunAlgorithms(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantAlg    string
		wantSuffix string
	}{
		{
			name:       "default",
			wantAlg:    `Algorithm is "ROT13"`,
			wantSuffix: "NOP klm 123\n",
		},
		{
			name:       "rot13",
			args:       []string{"-alg", "rot13"},
			wantAlg:    `Algorithm is "ROT13"`,
			wantSuffix: "NOP klm 123\n",
		},
		{
			name:       "atbash",
			args:       []string{"-alg", "atbash"},
			wantAlg:    `Algorithm is "ATBASH"`,
			wantSuffix: "ZYX cba 123\n",
		},
		{
			name:       "atbashrot13",
			args:       []string{"-alg", "atbashrot13"},
			wantAlg:    `Algorithm is "ATBASHROT13"`,
			wantSuffix: "MLK pon 123\n",
		},
		{
			name:       "rot13atbash",
			args:       []string{"-alg", "rot13atbash"},
			wantAlg:    `Algorithm is "ROT13ATBASH"`,
			wantSuffix: "MLK pon 123\n",
		},
		{
			name:       "unknown_falls_back_to_rot13",
			args:       []string{"-alg", "caesar"},
			wantAlg:    `Algorithm is "ROT13"`,
			wantSuffix: "NOP klm 123\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(strings.NewReader("ABC xyz 123\n"), &stdout, &stderr, tc.args)

			if code != 0 {
				t.Fatalf("run() code = %d, want 0; stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantAlg) {
				t.Fatalf("stdout = %q, want to contain %q", stdout.String(), tc.wantAlg)
			}
			if !strings.HasSuffix(stdout.String(), tc.wantSuffix) {
				t.Fatalf("stdout = %q, want suffix %q", stdout.String(), tc.wantSuffix)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(strings.NewReader("ABC"), &stdout, &stderr, []string{"-h"})

	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage of crypt4kids:") {
		t.Fatalf("stdout = %q, want usage", stdout.String())
	}
	if !strings.Contains(stdout.String(), "-plain") {
		t.Fatalf("stdout = %q, want -plain flag", stdout.String())
	}
}

func TestRunFlagError(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(strings.NewReader("ABC"), &stdout, &stderr, []string{"-unknown"})

	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "error parsing flags") {
		t.Fatalf("stderr = %q, want parse error", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage of crypt4kids:") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunCopyError(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(errorReader{}, &stdout, &stderr, nil)

	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "crypt4kids") {
		t.Fatalf("stdout = %q, want intro", stdout.String())
	}
	if !strings.Contains(stderr.String(), "error copying from reader to stdout") {
		t.Fatalf("stderr = %q, want copy error", stderr.String())
	}
}

func TestRunPlainFlagForcesStreamingWithTerminal(t *testing.T) {
	stdin := terminalInput{Reader: strings.NewReader("ABC\n")}
	var stdout terminalBuffer
	var stderr bytes.Buffer

	code := run(stdin, &stdout, &stderr, []string{"-plain", "-alg", "atbash"})

	if code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), `Algorithm is "ATBASH"`) {
		t.Fatalf("stdout = %q, want atbash plain mode", stdout.String())
	}
	if !strings.HasSuffix(stdout.String(), "ZYX\n") {
		t.Fatalf("stdout = %q, want atbash output", stdout.String())
	}
}

func TestShouldRunArcadeForInteractiveTerminal(t *testing.T) {
	stdin := terminalInput{Reader: strings.NewReader("")}
	var stdout terminalBuffer

	if !shouldRunArcade(stdin, &stdout, false) {
		t.Fatal("shouldRunArcade() = false, want true for terminal stdin/stdout")
	}
	if shouldRunArcade(stdin, &stdout, true) {
		t.Fatal("shouldRunArcade() = true, want false when plain mode is forced")
	}
	if shouldRunArcade(strings.NewReader("ABC"), &stdout, false) {
		t.Fatal("shouldRunArcade() = true, want false for piped stdin")
	}
}

func TestArcadeModelEncryptFlow(t *testing.T) {
	model := newCyberpunkArcadeModel("rot13")
	model = updateArcadeModel(t, model, textKey("2"))
	model = updateArcadeModel(t, model, textKey("t"))
	for _, r := range "ABC xyz 123" {
		model = updateArcadeModel(t, model, textKey(string(r)))
	}
	model = updateArcadeModel(t, model, codeKey(tea.KeyEnter))
	model = updateArcadeModel(t, model, textKey("e"))

	if model.algorithm != "atbash" {
		t.Fatalf("model.algorithm = %q, want atbash", model.algorithm)
	}
	if got, want := string(model.input), "ABC xyz 123"; got != want {
		t.Fatalf("model.input = %q, want %q", got, want)
	}
	if !model.hasOutput {
		t.Fatal("model.hasOutput = false, want true")
	}
	if got, want := model.output, "ZYX cba 123"; got != want {
		t.Fatalf("model.output = %q, want %q", got, want)
	}
	if model.mode != arcadeModeCommand {
		t.Fatalf("model.mode = %v, want command mode", model.mode)
	}
}

func TestArcadeModelClear(t *testing.T) {
	model := newCyberpunkArcadeModel("rot13")
	model.input = []rune("ABC")
	model.cursor = len(model.input)
	model.output = "NOP"
	model.hasOutput = true

	model = updateArcadeModel(t, model, textKey("c"))

	if string(model.input) != "" {
		t.Fatalf("model.input = %q, want empty", string(model.input))
	}
	if model.output != "" {
		t.Fatalf("model.output = %q, want empty", model.output)
	}
	if model.hasOutput {
		t.Fatal("model.hasOutput = true, want false")
	}
	if model.status != "BUFFER PURGED" {
		t.Fatalf("model.status = %q, want clear status", model.status)
	}
}

func TestArcadeModelViewHasCyberpunkPixelArt(t *testing.T) {
	model := newCyberpunkArcadeModel("rot13")
	content := model.View().Content

	for _, want := range []string{
		"CRYPT4KIDS // CYBER ARCADE",
		"NEON CITY",
		"PLAINTEXT TERMINAL",
		"CIPHER OUTPUT",
		"[1] ROT13",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("view content = %q, want to contain %q", content, want)
		}
	}
}

func TestMain(t *testing.T) {
	stdin := tempInputFile(t, "ABC")
	stdoutReader, stdoutWriter := pipe(t)
	stderrReader, stderrWriter := pipe(t)

	oldArgs := os.Args
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldExit := osExit
	t.Cleanup(func() {
		os.Args = oldArgs
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		osExit = oldExit
	})

	var exitCode int
	os.Args = []string{"crypt4kids", "-alg", "atbash"}
	os.Stdin = stdin
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	osExit = func(code int) {
		exitCode = code
	}

	main()

	mustClose(t, stdoutWriter)
	mustClose(t, stderrWriter)
	stdout := readAll(t, stdoutReader)
	stderr := readAll(t, stderrReader)

	if exitCode != 0 {
		t.Fatalf("main() exit code = %d, want 0", exitCode)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if !strings.HasSuffix(stdout, "ZYX") {
		t.Fatalf("stdout = %q, want atbash output", stdout)
	}
}

var errorReaderErr = errors.New("reader failed")

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errorReaderErr
}

func tempInputFile(t *testing.T, input string) *os.File {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := f.WriteString(input); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}

	return f
}

func pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe() error = %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
	})

	return r, w
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	return string(b)
}

func mustClose(t *testing.T, c io.Closer) {
	t.Helper()

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func updateArcadeModel(t *testing.T, model cyberpunkArcadeModel, msg tea.Msg) cyberpunkArcadeModel {
	t.Helper()

	updated, _ := model.Update(msg)
	next, ok := updated.(cyberpunkArcadeModel)
	if !ok {
		t.Fatalf("Update() returned %T, want cyberpunkArcadeModel", updated)
	}

	return next
}

func textKey(text string) tea.KeyPressMsg {
	runes := []rune(text)
	code := tea.KeyExtended
	if len(runes) == 1 {
		code = runes[0]
	}
	if text == " " {
		code = tea.KeySpace
	}

	return tea.KeyPressMsg(tea.Key{Text: text, Code: code})
}

func codeKey(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: code})
}

type terminalInput struct {
	*strings.Reader
}

func (terminalInput) Stat() (os.FileInfo, error) {
	return fakeFileInfo{mode: os.ModeCharDevice}, nil
}

type terminalBuffer struct {
	bytes.Buffer
}

func (*terminalBuffer) Stat() (os.FileInfo, error) {
	return fakeFileInfo{mode: os.ModeCharDevice}, nil
}

type fakeFileInfo struct {
	mode os.FileMode
}

func (f fakeFileInfo) Name() string {
	return "tty"
}

func (f fakeFileInfo) Size() int64 {
	return 0
}

func (f fakeFileInfo) Mode() os.FileMode {
	return f.mode
}

func (f fakeFileInfo) ModTime() time.Time {
	return time.Time{}
}

func (f fakeFileInfo) IsDir() bool {
	return false
}

func (f fakeFileInfo) Sys() any {
	return nil
}
