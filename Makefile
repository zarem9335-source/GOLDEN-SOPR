# GOLDEN SOPR — Makefile (binary: golden-sopr, symlink: sopr)
# Module path stays github.com/soprpack/soprpack (see README).
BIN := golden-sopr
PKG := github.com/soprpack/soprpack
GO  := go

.PHONY: build test vet clean release fmt

build:
	$(GO) build -trimpath -o $(BIN) .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w main.go cmd internal

clean:
	rm -f $(BIN) sopr soprpack-*.tar.gz

release: clean
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o dist/$(BIN)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o dist/$(BIN)-linux-arm64 .
	cd dist && sha256sum $(BIN)-linux-* > SHA256SUMS.txt
