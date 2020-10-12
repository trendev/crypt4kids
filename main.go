package main

import (
	"bufio"
	"io"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	r := rot13Reader{reader}
	io.Copy(os.Stdout, r)
}
