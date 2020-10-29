package encoding

import (
	"fmt"
	"io"
)

//Reader is a reader encoding with a specific algorithm
type Reader struct {
	reader io.Reader
	fn     func(b byte) byte
}

func (r Reader) Read(p []byte) (n int, err error) {

	n, err = r.reader.Read(p)

	if err != nil && err != io.EOF {
		return n, fmt.Errorf("can not read bytes %s : %v", p, err)
	}

	for i := 0; i < n; i++ {
		p[i] = r.fn(p[i])
	}
	return
}

//NewRot13Reader creates a new Reader using rot13 algorithm
func NewRot13Reader(reader io.Reader) *Reader {
	return &Reader{reader, rot13}
}

//NewAtBashReader creates a new Reader using atbash algorithm
func NewAtBashReader(reader io.Reader) *Reader {
	return &Reader{reader, atbash}
}

func rot13(b byte) byte {
	var a, z byte
	switch {
	case 'a' <= b && b <= 'z':
		a, z = 'a', 'z'
	case 'A' <= b && b <= 'Z':
		a, z = 'A', 'Z'
	default:
		return b
	}
	return (b-a+13)%(z-a+1) + a
}

func atbash(b byte) byte {
	var a, z byte
	switch {
	case 'a' <= b && b <= 'z':
		a, z = 'a', 'z'
	case 'A' <= b && b <= 'Z':
		a, z = 'A', 'Z'
	default:
		return b
	}
	return z + a - b
}
