tidy:
	@go mod tidy
	@echo "Done!"

upd:
	@go get -u ./...
	@echo "Done!"

fmt:
	@go fmt ./...

test: 
	@go test -v ./...
	@echo "Done!"

it:
	@go test -v ./... -tags=it
	@echo "Done!"

lint:
	@echo "==> Checking source code with golangci-lint..."
	@golangci-lint run

lintfix:
	@echo "==> Checking source code with golangci-lint..."
	@golangci-lint run --fix

test-integration:
	@docker run --rm -v $(PWD):/app -w /app python:3.9-slim python test.py
