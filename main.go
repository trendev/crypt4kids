package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/trendev/crypt4kids/encoding"
)

func main() {
	a := flag.String("a", "rot13", "algorithm : \"rot13\" or \"atbash\"")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)

	var r *encoding.Reader
	switch *a {
	case "atbash":
		r = encoding.NewAtBashReader(reader)
	default:
		r = encoding.NewRot13Reader(reader)
	}

	fmt.Println("Enter your text and it will be translated :")

	_, err := io.Copy(os.Stdout, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error copying from reader to stdout : %v\n", err)
	}
}
