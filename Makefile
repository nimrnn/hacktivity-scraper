.PHONY: build vet run

build:
	go build -o bin/scraper ./cmd/scraper

vet:
	go build ./... && go vet ./...

run:
	go run ./cmd/scraper
