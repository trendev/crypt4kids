package encoding

import (
	"io"
	"strings"
	"testing"
)

func TestRot13Reader(t *testing.T) {
	s := "Trendev Consulting"
	b := make([]byte, len(s))
	r := NewRot13Reader(strings.NewReader(s))
	es := "Geraqri Pbafhygvat"

	_, err := io.ReadFull(r, b)
	if err != nil {
		t.Errorf("cannot read from reader to buffer : %v\n", err)
		t.FailNow()
	}

	ds := string(b)

	if es != ds {
		t.Errorf("%s should be encoded as %s and not %s", s, es, ds)
		t.FailNow()
	}

}
