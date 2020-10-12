package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/trendev/crypt4kids/rot13"
)

func main() {
	fmt.Println("Enter your text and it will be translated :")
	reader := bufio.NewReader(os.Stdin)
	r := rot13.NewReader(reader)
	_, err := io.Copy(os.Stdout, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error copying from reader to stdout : %v\n", err)
	}
}
