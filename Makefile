.PHONY: build run clean test help

BINARY_NAME=restrike
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-X main.version=0.1.0 -X main.commit=`git rev-parse --short HEAD`"

help:
	@echo "REStrike Makefile"
	@echo "Comandos disponibles:"
	@echo "  make build      - Compilar la aplicación"
	@echo "  make run        - Compilar y ejecutar"
	@echo "  make clean      - Limpiar binarios"
	@echo "  make test       - Ejecutar tests"
	@echo "  make deps       - Descargar dependencias"
	@echo "  make install    - Instalar globalmente"

build:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) ./cmd/restrike

run: build
	./$(BINARY_NAME)

run-headless: build
	./$(BINARY_NAME) -headless -target 192.168.1.0/24

clean:
	$(GO) clean
	rm -f $(BINARY_NAME)

test:
	$(GO) test -v ./...

deps:
	$(GO) mod download
	$(GO) mod tidy

install: build
	install -m 755 $(BINARY_NAME) /usr/local/bin/

fmt:
	$(GO) fmt ./...

lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...
