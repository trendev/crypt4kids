# crypt4kids
[![Test, Build and Save](https://github.com/trendev/crypt4kids/actions/workflows/build.yml/badge.svg)](https://github.com/trendev/crypt4kids/actions/workflows/build.yml)

[![codecov](https://codecov.io/gh/trendev/crypt4kids/branch/main/graph/badge.svg?token=B8BATGUXMS)](https://codecov.io/gh/trendev/crypt4kids)

A simple crypto tool for kids :books:

## :zap: Run (using golang)

Clone the repo and execute the following command:

```sh
go run ./cmd
```

When stdin and stdout are connected to a terminal, crypt4kids starts in a full-screen cyberpunk arcade mode powered by [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

The arcade mode renders a neon 8-bit terminal cabinet with pixel-art city graphics, cartridge-style algorithm buttons, a plaintext panel, and a cipher output panel.

Arcade controls:

- `1`, `2`, `3`, `4`: select an algorithm
- `t`: enter type mode
- `Enter`: leave type mode, or encrypt from command mode
- `e`: encrypt from command mode
- `c`: clear the text and output
- `q`: quit

Type mode controls:

- regular text keys: edit the plaintext buffer
- left/right arrows: move the input cursor
- `Backspace` / `Delete`: edit text
- `Esc`: leave type mode without encrypting

You can also use crypt4kids as a plain stdin/stdout tool:

```sh
printf 'Trendev rox\n' | go run ./cmd
```

Using the default `rot13` algorithm, this prints:

```text
crypt4kids
Algorithm is "ROT13"

Enter your text and it will be translated:
Geraqri ebk
```

To force plain mode while running from an interactive terminal:

```sh
go run ./cmd -plain
```

When using `-plain` interactively, press `Ctrl-D` to finish the input stream.

## :video_game: Browser arcade

Run the local browser arcade:

```sh
go run ./cmd -web
```

Then open:

```text
http://127.0.0.1:8787
```

The browser arcade is an 80s security-game interface with pixel-art operator portraits, a faux-3D vault view, cipher cartridges, and CRT-style plaintext/output panels. Encryption is served by the same local Go cipher code used by the CLI.

Browser controls:

- choose a cipher cartridge: `ROT13`, `ATBASH`, `A+B`, or `B+A`
- type plaintext in the CRT input panel
- `ENCRYPT`: translate the current text
- `COPY`: copy the latest cipher output
- `CLEAR`: reset the input and output panels

Use a different address if needed:

```sh
go run ./cmd -web -addr 127.0.0.1:9090
```

## :rocket: Run (using docker)

Just run:

```sh
docker run -it --rm ghcr.io/trendev/crypt4kids
```

For plain streaming mode:

```sh
printf 'Trendev rox\n' | docker run -i --rm ghcr.io/trendev/crypt4kids
```

For browser arcade mode with Docker:

```sh
docker run --rm -p 8787:8787 ghcr.io/trendev/crypt4kids -web -addr :8787
```

## :sweat_smile: Need Help ?

Run the following command if you need to get app usage:

```sh
docker run -it --rm ghcr.io/trendev/crypt4kids -h
```

Available flags:

- `-alg`: set the algorithm. Supported values are `rot13`, `atbash`, `atbashrot13`, and `rot13atbash`. The default is `rot13`.
- `-addr`: set the browser arcade server address. The default is `127.0.0.1:8787`.
- `-plain`: use the line-oriented stdin/stdout interface instead of arcade mode.
- `-web`: serve the browser arcade interface.

Examples:

```sh
go run ./cmd -alg atbash
printf 'ABC xyz 123\n' | go run ./cmd -alg atbash
go run ./cmd -web
```
