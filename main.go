package main

import (
	"bufio"
	"io"
	"os"
)

func main() {
	r := rot13Reader{bufio.NewReader(os.Stdin)}
	io.Copy(os.Stdout, r)
}
