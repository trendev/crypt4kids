package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
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

func TestRunInteractiveTerminalUsesArcade(t *testing.T) {
	stdin := terminalInput{Reader: strings.NewReader("q\n")}
	var stdout terminalBuffer
	var stderr bytes.Buffer

	code := run(stdin, &stdout, &stderr, nil)

	if code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "C I P H E R  A R C A D E") {
		t.Fatalf("stdout = %q, want arcade screen", stdout.String())
	}
	if strings.Contains(stdout.String(), "Enter your text and it will be translated:") {
		t.Fatalf("stdout = %q, want arcade mode instead of plain prompt", stdout.String())
	}
	if !strings.Contains(stdout.String(), "GAME OVER") {
		t.Fatalf("stdout = %q, want quit message", stdout.String())
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

func TestRunArcadeEncryptFlow(t *testing.T) {
	stdin := strings.NewReader("2\nt\nABC xyz 123\ne\nq\n")
	var stdout, stderr bytes.Buffer

	code := runArcade(stdin, &stdout, &stderr, "rot13", false)

	if code != 0 {
		t.Fatalf("runArcade() code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "ACTIVE ALGORITHM: ATBASH") {
		t.Fatalf("stdout = %q, want selected algorithm", stdout.String())
	}
	if !strings.Contains(stdout.String(), "OUTPUT: ZYX cba 123") {
		t.Fatalf("stdout = %q, want encrypted output", stdout.String())
	}
}

func TestRunArcadeClear(t *testing.T) {
	stdin := strings.NewReader("t\nABC\ne\nc\nq\n")
	var stdout, stderr bytes.Buffer

	code := runArcade(stdin, &stdout, &stderr, "rot13", false)

	if code != 0 {
		t.Fatalf("runArcade() code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	got := stdout.String()
	lastLoadedInput := strings.LastIndex(got, "INPUT : ABC")
	lastEmptyInput := strings.LastIndex(got, "INPUT : <empty>")
	if lastLoadedInput == -1 {
		t.Fatalf("stdout = %q, want loaded input before clear", got)
	}
	if lastEmptyInput <= lastLoadedInput {
		t.Fatalf("stdout = %q, want empty input after clear", got)
	}

	lastEncryptedOutput := strings.LastIndex(got, "OUTPUT: NOP")
	lastWaitingOutput := strings.LastIndex(got, "OUTPUT: <waiting for encrypt>")
	if lastEncryptedOutput == -1 {
		t.Fatalf("stdout = %q, want encrypted output before clear", got)
	}
	if lastWaitingOutput <= lastEncryptedOutput {
		t.Fatalf("stdout = %q, want waiting output after clear", got)
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
