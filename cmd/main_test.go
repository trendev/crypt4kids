package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
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
