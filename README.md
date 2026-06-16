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

## :rocket: Run (using docker)

Just run:

```sh
docker run -it --rm ghcr.io/trendev/crypt4kids
```

For plain streaming mode:

```sh
printf 'Trendev rox\n' | docker run -i --rm ghcr.io/trendev/crypt4kids
```

## :sweat_smile: Need Help ?

Run the following command if you need to get app usage:

```sh
docker run -it --rm ghcr.io/trendev/crypt4kids -h
```

Available flags:

- `-alg`: set the algorithm. Supported values are `rot13`, `atbash`, `atbashrot13`, and `rot13atbash`. The default is `rot13`.
- `-plain`: use the line-oriented stdin/stdout interface instead of arcade mode.

Examples:

```sh
go run ./cmd -alg atbash
printf 'ABC xyz 123\n' | go run ./cmd -alg atbash
```
