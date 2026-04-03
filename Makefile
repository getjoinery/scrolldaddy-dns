VERSION ?= dev

.PHONY: build test clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o scrolldaddy-dns ./cmd/dns

test:
	go test ./...

clean:
	rm -f scrolldaddy-dns
