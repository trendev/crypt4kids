package encoding

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReader(t *testing.T) {
	const input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 123!"

	tests := []struct {
		name   string
		reader io.Reader
		want   string
	}{
		{
			name:   "rot13",
			reader: NewRot13Reader(strings.NewReader(input)),
			want:   "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm 123!",
		},
		{
			name:   "atbash",
			reader: NewAtBashReader(strings.NewReader(input)),
			want:   "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba 123!",
		},
		{
			name:   "rot13_atbash",
			reader: NewAtBashReader(NewRot13Reader(strings.NewReader(input))),
			want:   "MLKJIHGFEDCBAZYXWVUTSRQPONmlkjihgfedcbazyxwvutsrqpon 123!",
		},
		{
			name:   "atbash_rot13",
			reader: NewRot13Reader(NewAtBashReader(strings.NewReader(input))),
			want:   "MLKJIHGFEDCBAZYXWVUTSRQPONmlkjihgfedcbazyxwvutsrqpon 123!",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := io.ReadAll(tc.reader)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}

			if string(got) != tc.want {
				t.Fatalf("ReadAll() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReaderPassesThroughEOF(t *testing.T) {
	r := NewRot13Reader(eofReader{})

	buf := make([]byte, 1)
	n, err := r.Read(buf)

	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v, want %v", err, io.EOF)
	}
	if n != 0 {
		t.Fatalf("Read() n = %d, want 0", n)
	}
}

func TestReaderWrapsReadError(t *testing.T) {
	r := NewRot13Reader(errFooReader{})

	buf := make([]byte, 1)
	n, err := r.Read(buf)

	if !errors.Is(err, errFoo) {
		t.Fatalf("Read() error = %v, want wrapped %v", err, errFoo)
	}
	if n != 0 {
		t.Fatalf("Read() n = %d, want 0", n)
	}
}

func TestReaderEncodesBytesReturnedWithError(t *testing.T) {
	r := NewRot13Reader(partialErrReader{})

	buf := make([]byte, 3)
	n, err := r.Read(buf)

	if !errors.Is(err, errFoo) {
		t.Fatalf("Read() error = %v, want wrapped %v", err, errFoo)
	}
	if n != 3 {
		t.Fatalf("Read() n = %d, want 3", n)
	}
	if got, want := string(buf), "NOP"; got != want {
		t.Fatalf("Read() buffer = %q, want %q", got, want)
	}
}

func TestAtbash(t *testing.T) {
	tests := map[byte]byte{
		'a': 'z',
		'z': 'a',
		'b': 'y',
		'y': 'b',
		'f': 'u',
		'k': 'p',
		'm': 'n',
		'K': 'P',
		'M': 'N',
		'1': '1',
	}

	for input, want := range tests {
		t.Run(string(input), func(t *testing.T) {
			if got := atbash(input); got != want {
				t.Fatalf("atbash(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestRot13(t *testing.T) {
	tests := map[byte]byte{
		'a': 'n',
		'z': 'm',
		'b': 'o',
		'y': 'l',
		'f': 's',
		'k': 'x',
		'm': 'z',
		'M': 'Z',
		'A': 'N',
		'1': '1',
	}

	for input, want := range tests {
		t.Run(string(input), func(t *testing.T) {
			if got := rot13(input); got != want {
				t.Fatalf("rot13(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

type errFooReader struct{}

var errFoo = errors.New("ERRFOO")

func (errFooReader) Read([]byte) (int, error) {
	return 0, errFoo
}

type partialErrReader struct{}

func (partialErrReader) Read(p []byte) (int, error) {
	copy(p, "ABC")
	return 3, errFoo
}
