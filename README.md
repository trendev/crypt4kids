# crypt4kids
[![Test, Build and Save](https://github.com/trendev/crypt4kids/actions/workflows/build.yml/badge.svg)](https://github.com/trendev/crypt4kids/actions/workflows/build.yml)

[![codecov](https://codecov.io/gh/trendev/crypt4kids/branch/main/graph/badge.svg?token=B8BATGUXMS)](https://codecov.io/gh/trendev/crypt4kids)

A simple crypto tool for kids :books:

## :zap: Run (using golang)

Clone the repo and execute the following command:

`go run ./cmd` 

... and you can enter the text to translate, using `rot13` algorithm:

`Trendev rox`

should give:

`Geraqri ebk`

## :rocket: Run (using docker)
Just run:

`docker run -it --rm ghcr.io/trendev/crypt4kids`

## :sweat_smile: Need Help ?
Run the following command if you need to get app usage:

`docker run -it --rm ghcr.io/trendev/crypt4kids -h`

You can set the `-alg` flag if you want to change the algorithm. `rot13` or `atbash` or `atbashrot13` or `rot13atbash` are supported and **`rot13` is default one**.

