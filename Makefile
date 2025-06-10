NAME := bobctl
VERSION := 0.1.0
BUILD_DIR := bin

OS := $(shell /usr/local/opt/go/libexec/bin/go env GOOS)
ARCH := $(shell /usr/local/opt/go/libexec/bin/go env GOARCH)

# Output binary name
ifeq ($(OS),windows)
	BINARY_NAME := $(NAME).exe
else
	BINARY_NAME := $(NAME)
endif

OUTPUT_PATH := $(BUILD_DIR)/$(OS)/$(ARCH)/$(BINARY_NAME)

GO_FILES := $(shell find src -type f -name '*.go')

##@ General

.PHONY: all
all: build 

.PHONY: build
build: $(OUTPUT_PATH) 
 
$(OUTPUT_PATH): $(GO_FILES)
	@echo "Building $(NAME) for $(OS)/$(ARCH)..."
	@mkdir -p $(dir $(OUTPUT_PATH))
	/usr/local/opt/go/libexec/bin/go version
	/usr/local/opt/go/libexec/bin/go build -o $(OUTPUT_PATH) ./src/main.go
	@echo "Build complete: $(OUTPUT_PATH)"

.PHONY: clean
clean: ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

##@ Development

.PHONY: run
run: build ## Build and run the CLI
	@echo "Running $(NAME)..."
	@$(OUTPUT_PATH)
