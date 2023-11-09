# use goland:lastest instead of golang:alpine because go git is not available in alpine version
FROM golang:1.21 as builder
WORKDIR /go/src/crypt4kids
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o bin/cmd -v cmd/main.go

FROM scratch
COPY --from=builder /go/src/crypt4kids/bin/cmd /app/bin/
ENTRYPOINT ["/app/bin/cmd"]