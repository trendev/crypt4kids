package main

import (
	"io"
	"os"
	"strings"
)

func main() {
	s := strings.NewReader("Trendev rox")
	r := rot13Reader{s}
	io.Copy(os.Stdout, r)
}
