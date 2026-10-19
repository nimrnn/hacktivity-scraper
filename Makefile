.PHONY: build vet run cwe-index

build:
	go build -o bin/scraper ./cmd/scraper

vet:
	go build ./... && go vet ./...

run:
	go run ./cmd/scraper

cwe-index:
	python3 scripts/gen_cwe_index.py
