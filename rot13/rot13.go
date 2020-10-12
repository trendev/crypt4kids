package rot13

import (
	"fmt"
	"io"
)

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

//Reader is a reader encoding with rot13 algorithm
type Reader struct {
	reader io.Reader
}

//NewReader creates a new Rot13Reader
func NewReader(reader io.Reader) *Reader {
	return &Reader{reader}
}

func (r Reader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err != nil {
		if err != io.EOF { // this one is more important than EOF error
			return 0, fmt.Errorf("can not read bytes %s : %v", p, err)
		}
		return n, err
	}
	for i := 0; i < n; i++ {
		p[i] = rot13(p[i])
	}
	return n, nil
}
