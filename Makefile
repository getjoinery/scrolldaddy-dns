VERSION ?= dev

.PHONY: build test clean release

build:
	go build -ldflags "-X main.version=$(VERSION)" -o scrolldaddy-dns ./cmd/dns

test:
	go test -race ./...

release:
	@chmod +x build_installer.sh
	./build_installer.sh $(VERSION)

clean:
	rm -f scrolldaddy-dns scrolldaddy-dns-installer.sh
