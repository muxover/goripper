.PHONY: build test vet lint check

build:
	go build ./...

test:
	go test -race -count=1 -timeout 120s ./...

vet:
	go vet ./...

lint:
	staticcheck ./...

check: vet lint test
