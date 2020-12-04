package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Delta456/box-cli-maker/v2"
	"github.com/trendev/crypt4kids/pkg/encoding"
)

func main() {
	a := flag.String("alg", "rot13", "algorithm : \"rot13\" or \"atbash\" or \"atbashrot13\" or \"rot13atbash\"")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)

	var r *encoding.Reader
	switch *a {
	case "atbash":
		r = encoding.NewAtBashReader(reader)
	case "atbashrot13":
		r = encoding.NewRot13Reader(encoding.NewAtBashReader(reader))
	case "rot13atbash":
		r = encoding.NewAtBashReader(encoding.NewRot13Reader(reader))
	default:
		r = encoding.NewRot13Reader(reader)
	}

	b := box.New(box.Config{
		Px:           2,
		Py:           2,
		ContentAlign: "Center",
		Type:         "Double",
		Color:        "HiCyan",
	})
	b.Print("crypt4kids", fmt.Sprintf("Algorithm is %q", strings.ToUpper(*a)))

	fmt.Println("Enter your text and it will be translated :")

	_, err := io.Copy(os.Stdout, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error copying from reader to stdout : %v\n", err)
	}
}
