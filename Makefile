run: build
	./bin/crypt4kids
build: clean
	go build -o bin/crypt4kids -v ./cmd
clean:
	rm -rf ./bin
test:
	go test -v ./...
