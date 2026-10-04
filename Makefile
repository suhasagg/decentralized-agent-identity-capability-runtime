test:
	go test -race ./...

run:
	ADMIN_TOKEN=dev-admin go run ./cmd/server

build:
	go build ./cmd/server
