#!/bin/bash
set -e

# --- Configuration ---
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color
GO_VERSION_REQUIRED="1.25.0"
GO_VERSION_TARGET="1.25.11"
XCADDY_VERSION="latest"
GEOLITE2_DB_URL="https://git.io/GeoLite2-Country.mmdb"
GEOLITE2_DB_FILE="GeoLite2-Country.mmdb"

# Default modules - can be overridden with environment variables
WAF_MODULE=${WAF_MODULE:-"github.com/fabriziosalmi/caddy-waf@latest"}
# Add additional modules here, comma-separated in EXTRA_MODULES env var
# Example: EXTRA_MODULES="github.com/greenpau/caddy-security@latest,github.com/example/module@latest"
EXTRA_MODULES=${EXTRA_MODULES:-""}

# --- Helper Functions ---
print_success() {
    echo -e "${GREEN}✅ Success: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ Warning: $1${NC}"
}

print_info() {
    echo -e "ℹ️  Info: $1${NC}"
}

print_error() {
    echo -e "${RED}❌ Error: $1${NC}"
    echo -e "${RED}   $1${NC}" >&2
    exit 1
}

check_command_exists() {
    if ! command -v "$1" &> /dev/null; then
        return 1 # Command not found
    else
        return 0 # Command found
    fi
}

ensure_go_installed() {
    if ! check_command_exists go; then
        print_info "Go not found. Installing Go $GO_VERSION_TARGET..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            install_go_linux
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            install_go_macos
        else
            print_error "Unsupported OS type: $OSTYPE"
        fi
    else
        check_go_version
    fi
}

check_go_version() {
    local version
    version=$(go version 2>&1 | awk '{print $3}' | sed 's/go//')
    if [[ "$version" == *"error"* ]]; then
        print_warning "Error checking Go version. Attempting to proceed anyway."
        return
    fi

    # Compare versions (simple string comparison, assumes semantic versioning)
    if [[ "$version" < "$GO_VERSION_REQUIRED" ]]; then
        print_warning "Go version $version is older than required version $GO_VERSION_REQUIRED."
        print_info "Installing Go $GO_VERSION_TARGET..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            install_go_linux
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            install_go_macos
        else
            print_error "Unsupported OS type: $OSTYPE"
        fi
    else
        print_info "Go version $version is installed (minimum required: $GO_VERSION_REQUIRED)."
    fi
}

ensure_xcaddy_installed() {
    if ! check_command_exists xcaddy; then
        print_info "xcaddy not found. Installing xcaddy..."
        install_xcaddy
    else
        print_info "xcaddy is already installed."
    fi
}

install_xcaddy() {
    print_info "Installing xcaddy $XCADDY_VERSION..."
    GOBIN="$(go env GOBIN)"
    if [ -z "$GOBIN" ]; then
        GOBIN="$HOME/go/bin" # Default GOBIN if not set
    fi
    go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" || print_error "Failed to install xcaddy."
    export PATH="$PATH:$GOBIN" # Ensure PATH is updated in current shell
    print_success "xcaddy $XCADDY_VERSION installed successfully."
}

download_geolite2_db() {
    if [ ! -f "$GEOLITE2_DB_FILE" ]; then
        print_info "Downloading GeoLite2 Country database..."
        if check_command_exists wget; then
            wget -q "$GEOLITE2_DB_URL" -O "$GEOLITE2_DB_FILE" || print_error "Failed to download GeoLite2 database."
        elif check_command_exists curl; then
            curl -s "$GEOLITE2_DB_URL" -o "$GEOLITE2_DB_FILE" || print_error "Failed to download GeoLite2 database."
        else
            print_error "Neither wget nor curl is installed. Cannot download GeoLite2 database."
        fi
        print_success "GeoLite2 database downloaded."
    else
        print_info "GeoLite2 database already exists."
    fi
}

build_caddy_with_modules() {
    print_info "Building Caddy with modules..."
    
    # Start building the xcaddy command
    CMD="xcaddy build --with $WAF_MODULE"
    
    # Add any extra modules
    if [ -n "$EXTRA_MODULES" ]; then
        IFS=',' read -ra MODULES <<< "$EXTRA_MODULES"
        for MODULE in "${MODULES[@]}"; do
            CMD="$CMD --with $MODULE"
        done
    fi
    
    print_info "Running command: $CMD"
    eval $CMD || print_error "Failed to build Caddy with modules."
    
    print_success "Caddy built successfully with the following modules:"
    print_info "- $WAF_MODULE"
    if [ -n "$EXTRA_MODULES" ]; then
        IFS=',' read -ra MODULES <<< "$EXTRA_MODULES"
        for MODULE in "${MODULES[@]}"; do
            print_info "- $MODULE"
        done
    fi
}

format_caddyfile() {
    if [ -f "Caddyfile" ]; then
        print_info "Formatting Caddyfile..."
        ./caddy fmt --overwrite Caddyfile || print_warning "Failed to format Caddyfile."
        print_success "Caddyfile formatted."
    else
        print_info "No Caddyfile found to format."
    fi
}

check_modules() {
    print_info "Checking loaded modules..."
    ./caddy list-modules | grep -E "(waf|security)" || print_warning "Modules may not be properly loaded."
}

# --- OS Specific Functions ---

install_go_linux() {
    print_info "Installing Go $GO_VERSION_TARGET for Linux..."
    # Download and install Go
    wget -q https://golang.org/dl/go${GO_VERSION_TARGET}.linux-amd64.tar.gz -O go.tar.gz || print_error "Failed to download Go."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
    print_success "Go $GO_VERSION_TARGET installed successfully on Linux."
}

install_go_macos() {
    print_info "Installing Go $GO_VERSION_TARGET for macOS..."
    # Download and install Go
    curl -sL https://golang.org/dl/go${GO_VERSION_TARGET}.darwin-amd64.tar.gz -o go.tar.gz || print_error "Failed to download Go."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
    print_success "Go $GO_VERSION_TARGET installed successfully on macOS."
}

# --- Main Script ---

print_info "Starting setup for Caddy with multiple modules..."

# Display selected modules
print_info "Will install the following modules:"
print_info "- WAF Module: $WAF_MODULE"
if [ -n "$EXTRA_MODULES" ]; then
    print_info "- Extra Modules: $EXTRA_MODULES"
fi

# Prompt user to confirm
read -p "Continue with these modules? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    print_info "Installation cancelled by user."
    exit 0
fi

ensure_go_installed
ensure_xcaddy_installed
download_geolite2_db
build_caddy_with_modules
format_caddyfile
check_modules

print_success "Setup completed! You now have Caddy built with WAF and your selected modules."
print_info "To run Caddy: ./caddy run"
print_info "For a list of all installed modules: ./caddy list-modules"