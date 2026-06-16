package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/trendev/crypt4kids/pkg/encoding"
)

var osExit = os.Exit

func main() {
	osExit(run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:]))
}

func run(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	flags := flag.NewFlagSet("crypt4kids", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	alg := flags.String("alg", "rot13", `algorithm: "rot13", "atbash", "atbashrot13", or "rot13atbash"`)
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "error parsing flags: %v\n", err)
		printUsage(stderr)
		return 2
	}

	reader := bufio.NewReader(stdin)
	effectiveAlg := normalizeAlgorithm(*alg)
	r := newAlgorithmReader(effectiveAlg, reader)

	fmt.Fprintln(stdout, "crypt4kids")
	fmt.Fprintf(stdout, "Algorithm is %q\n\n", strings.ToUpper(effectiveAlg))
	fmt.Fprintln(stdout, "Enter your text and it will be translated:")

	if _, err := io.Copy(stdout, r); err != nil {
		fmt.Fprintf(stderr, "error copying from reader to stdout: %v\n", err)
		return 1
	}

	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage of crypt4kids:")
	fmt.Fprintln(w, `  -alg string`)
	fmt.Fprintln(w, `        algorithm: "rot13", "atbash", "atbashrot13", or "rot13atbash" (default "rot13")`)
}

func normalizeAlgorithm(alg string) string {
	switch alg {
	case "atbash", "atbashrot13", "rot13atbash":
		return alg
	default:
		return "rot13"
	}
}

func newAlgorithmReader(alg string, reader io.Reader) io.Reader {
	switch alg {
	case "atbash":
		return encoding.NewAtBashReader(reader)
	case "atbashrot13":
		return encoding.NewRot13Reader(encoding.NewAtBashReader(reader))
	case "rot13atbash":
		return encoding.NewAtBashReader(encoding.NewRot13Reader(reader))
	default:
		return encoding.NewRot13Reader(reader)
	}
}
