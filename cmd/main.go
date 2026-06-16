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
	plain := flags.Bool("plain", false, "use plain stdin/stdout mode instead of the arcade interface")
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

	effectiveAlg := normalizeAlgorithm(*alg)
	if shouldRunArcade(stdin, stdout, *plain) {
		return runArcade(stdin, stdout, stderr, effectiveAlg)
	}

	return runPlain(stdin, stdout, stderr, effectiveAlg)
}

func runPlain(stdin io.Reader, stdout, stderr io.Writer, alg string) int {
	reader := bufio.NewReader(stdin)
	r := newAlgorithmReader(alg, reader)

	fmt.Fprintln(stdout, "crypt4kids")
	fmt.Fprintf(stdout, "Algorithm is %q\n\n", algorithmDisplayName(alg))
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
	fmt.Fprintln(w, `  -plain`)
	fmt.Fprintln(w, `        use plain stdin/stdout mode instead of the arcade interface`)
}

func normalizeAlgorithm(alg string) string {
	switch alg {
	case "atbash", "atbashrot13", "rot13atbash":
		return alg
	default:
		return "rot13"
	}
}

func algorithmDisplayName(alg string) string {
	return strings.ToUpper(normalizeAlgorithm(alg))
}

func encodeString(alg, text string) string {
	var out strings.Builder
	_, _ = io.Copy(&out, newAlgorithmReader(alg, strings.NewReader(text)))
	return out.String()
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

func shouldRunArcade(stdin io.Reader, stdout io.Writer, forcePlain bool) bool {
	if forcePlain {
		return false
	}

	return isTerminal(stdin) && isTerminal(stdout)
}

func isTerminal(value any) bool {
	file, ok := value.(interface {
		Stat() (os.FileInfo, error)
	})
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
