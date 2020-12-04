package encoding

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReader(t *testing.T) {
	s := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tt := []struct {
		name   string
		reader *Reader
		result string
	}{
		{"rot13", NewRot13Reader(strings.NewReader(s)), "NOPQRSTUVWXYZABCDEFGHIJKLM"},
		{"atbash", NewAtBashReader(strings.NewReader(s)), "ZYXWVUTSRQPONMLKJIHGFEDCBA"},
		{"rot13 + atbash", NewAtBashReader(NewRot13Reader(strings.NewReader(s))), "MLKJIHGFEDCBAZYXWVUTSRQPON"},
		{"atbash + rot13", NewRot13Reader(NewAtBashReader(strings.NewReader(s))), "MLKJIHGFEDCBAZYXWVUTSRQPON"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, len(s))
			_, err := io.ReadFull(tc.reader, b)
			if err != nil {
				t.Errorf("cannot read from reader to buffer : %v\n", err)
			}

			ds := string(b)

			if tc.result != ds {
				t.Errorf("%s should be encoded as %s and not %s", s, tc.result, ds)
			}
		})
	}

}

type eofReader struct{}

func (eofReader) Read(p []byte) (n int, err error) {
	err = io.EOF
	return
}

type errFooReader struct{}

var errFoo = errors.New("ERRFOO")

func (errFooReader) Read(p []byte) (n int, err error) {
	err = errFoo
	return
}

func TestReaderWithError(t *testing.T) {

	tt := []struct {
		name string
		r    *Reader
		e    error
	}{
		{"EOF", &Reader{reader: &eofReader{}}, io.EOF},
		{"ERRFOO", &Reader{reader: &errFooReader{}}, errFoo},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, 1)
			n, err := io.ReadFull(tc.r, b)

			if !errors.Is(err, tc.e) {
				t.Errorf("want %v, got %v", tc.e, err)
			}

			if n != 0 {
				t.Errorf("no bit should have been read : bits read = %v", n)
			}
		})
	}

}
