# Go-TARSy-bot Makefile

# Variables
BINARY_NAME=go-tarsy-bot
MAIN_PATH=./cmd/server
BUILD_DIR=./build
GO_FILES=$(shell find . -name "*.go" -type f)

# Default target
.PHONY: all
all: clean build

# Build the application
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

# Build for production
.PHONY: build-prod
build-prod:
	@echo "Building $(BINARY_NAME) for production..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

# Run the application
.PHONY: run
run:
	@echo "Running $(BINARY_NAME)..."
	@go run $(MAIN_PATH)

# Run with development environment
.PHONY: dev
dev:
	@echo "Running $(BINARY_NAME) in development mode..."
	@GO_ENV=development go run $(MAIN_PATH)

# Run backend with dashboard (full development stack)
.PHONY: dev-full
dev-full:
	@echo "Starting full development stack (backend + dashboard)..."
	@echo "Configuration loaded from .env file"
	@echo "Starting backend..."
	@(GO_ENV=development go run $(MAIN_PATH) &)
	@sleep 3
	@echo "Starting dashboard..."
	@cd dashboard && npm run dev

# Run backend and dashboard in background
.PHONY: dev-background
dev-background:
	@echo "Starting backend and dashboard in background..."
	@echo "Configuration loaded from .env file"
	@(GO_ENV=development go run $(MAIN_PATH) &)
	@(cd dashboard && npm run dev &)
	@sleep 3
	@echo "Both services started in background"
	@echo "Use 'make stop' to stop all services"

# Install dashboard dependencies
.PHONY: setup-dashboard
setup-dashboard:
	@echo "Installing dashboard dependencies..."
	@cd dashboard && npm install

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@go clean

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	@golangci-lint run

# Vet code
.PHONY: vet
vet:
	@echo "Vetting code..."
	@go vet ./...

# Run quality checks
.PHONY: quality
quality: fmt vet lint

# Generate Go modules
.PHONY: mod-init
mod-init:
	@go mod init github.com/codeready/go-tarsy-bot

# Update dependencies
.PHONY: mod-update
mod-update:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

# Stop all running services
.PHONY: stop
stop:
	@echo "Stopping all services..."
	@pkill -f "go run.*cmd/server" || true
	@pkill -f "npm run dev" || true
	@pkill -f "vite" || true
	@echo "All services stopped"

# Setup development environment
.PHONY: setup
setup: deps setup-dashboard
	@echo "Setting up development environment..."
	@cp .env.template .env
	@echo "Please edit .env file with your configuration"
	@echo "Setup complete. Use 'make dev-full' to start both backend and dashboard"

# Database migrations (placeholder)
.PHONY: migrate
migrate:
	@echo "Running database migrations..."
	@go run $(MAIN_PATH) --migrate

# JWT Key Management
.PHONY: generate-jwt-keys
generate-jwt-keys:
	@echo "Generating JWT keys for authentication..."
	@go run ./cmd/generate-keys

.PHONY: validate-jwt-keys
validate-jwt-keys:
	@echo "Validating JWT keys..."
	@go run ./cmd/generate-keys --validate

.PHONY: force-generate-jwt-keys
force-generate-jwt-keys:
	@echo "Force generating JWT keys (overwriting existing)..."
	@go run ./cmd/generate-keys --force

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	@docker build -t go-tarsy-bot:latest .

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running Docker container..."
	@docker run -p 8000:8000 --env-file .env go-tarsy-bot:latest

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build            - Build the application"
	@echo "  build-prod       - Build for production (static binary)"
	@echo "  run              - Run the application"
	@echo "  dev              - Run in development mode (backend only)"
	@echo "  dev-full         - Run backend + dashboard (full stack)"
	@echo "  dev-background   - Run backend + dashboard in background"
	@echo "  stop             - Stop all running services"
	@echo "  deps             - Install Go dependencies"
	@echo "  setup-dashboard  - Install dashboard dependencies"
	@echo "  clean            - Clean build artifacts"
	@echo "  test             - Run tests"
	@echo "  test-coverage    - Run tests with coverage"
	@echo "  fmt              - Format code"
	@echo "  lint             - Lint code"
	@echo "  vet              - Vet code"
	@echo "  quality          - Run all quality checks"
	@echo "  setup            - Setup development environment (full)"
	@echo "  generate-jwt-keys - Generate JWT key pair for authentication"
	@echo "  validate-jwt-keys - Validate existing JWT keys"
	@echo "  force-generate-jwt-keys - Force regenerate JWT keys (overwrite existing)"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run Docker container"
	@echo "  help             - Show this help"