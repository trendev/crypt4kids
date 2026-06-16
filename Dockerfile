# use golang instead of golang:alpine because git is not available in the alpine image
FROM golang:1.26 AS builder
WORKDIR /go/src/crypt4kids
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o bin/cmd -v ./cmd

FROM scratch
COPY --from=builder /go/src/crypt4kids/bin/cmd /app/bin/
ENTRYPOINT ["/app/bin/cmd"]
