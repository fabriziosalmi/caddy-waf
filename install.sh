#!/bin/bash
set -e

# --- Configuration ---
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color
REPO_URL="https://github.com/fabriziosalmi/caddy-waf.git"
REPO_DIR="caddy-waf"
GO_VERSION_REQUIRED="1.25.0"
GO_VERSION_TARGET="1.25.11"
XCADDY_VERSION="latest" # or specify a version like "v0.3.7"
GEOLITE2_DB_URL="https://git.io/GeoLite2-Country.mmdb"
GEOLITE2_DB_FILE="GeoLite2-Country.mmdb"

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
    echo -e "${RED}   $1${NC}" >&2 # Print error to stderr as well
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
        install_go
    else
        check_go_version
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

clone_or_update_repo() {
    if [ -d "$REPO_DIR" ]; then
        print_info "$REPO_DIR directory already exists. Pulling latest changes..."
        cd "$REPO_DIR" || print_error "Could not change directory to $REPO_DIR"
        git pull origin main || print_error "Failed to pull $REPO_DIR updates." # Specify origin and branch
        cd .. # Go back to the script's directory
    else
        print_info "Cloning $REPO_DIR repository..."
        git clone "$REPO_URL" "$REPO_DIR" || print_error "Failed to clone repository from $REPO_URL."
    fi
    cd "$REPO_DIR" || print_error "Could not change directory to $REPO_DIR after clone/pull"
}

update_dependencies() {
    print_info "Running go mod tidy..."
    go mod tidy || print_error "Failed to run go mod tidy."
    print_success "Dependencies updated (go mod tidy)."

    print_info "Fetching Go modules..."
    go get -v github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/caddyconfig/caddyfile github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile github.com/caddyserver/caddy/v2/modules/caddyhttp github.com/oschwald/maxminddb-golang github.com/fsnotify/fsnotify github.com/fabriziosalmi/caddy-waf || print_error "Failed to fetch Go modules." # Combined go get
    print_success "Go modules fetched successfully."
}

download_geolite2_db() {
    if [ ! -f "$GEOLITE2_DB_FILE" ]; then
        print_info "Downloading GeoLite2 Country database..."
        wget -q "$GEOLITE2_DB_URL" -O "$GEOLITE2_DB_FILE" || print_error "Failed to download GeoLite2 database from $GEOLITE2_DB_URL." # Specify output file
        print_success "GeoLite2 database downloaded."
    else
        print_info "GeoLite2 database already exists."
    fi
}

build_caddy() {
    print_info "Building Caddy with caddy-waf module..."
    xcaddy build --with github.com/fabriziosalmi/caddy-waf=./ || print_error "Failed to build Caddy."
    print_success "Caddy built successfully."
}

format_caddyfile() {
    print_info "Formatting Caddyfile..."
    ./caddy fmt --overwrite || print_warning "Failed to format Caddyfile (This is a warning, Caddy might still run)." # Warning instead of error
    print_success "Caddyfile formatted."
}

run_caddy() {
    print_info "Starting Caddy server..."
    ./caddy run || print_error "Failed to start Caddy." # Keep as error, Caddy run failure is critical
    print_success "Caddy is running." # This line will likely not be reached in a typical run
}


# --- OS Specific Functions ---

install_go_linux() {
    print_info "Installing Go $GO_VERSION_TARGET for Linux..."
    GOBIN="/usr/local/go/bin" # Define GOBIN for clarity
    wget "https://go.dev/dl/go${GO_VERSION_TARGET}.linux-amd64.tar.gz" || print_error "Failed to download Go for Linux."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION_TARGET}.linux-amd64.tar.gz" || print_error "Failed to extract Go for Linux."
    rm "go${GO_VERSION_TARGET}.linux-amd64.tar.gz"
    export PATH="$PATH:$GOBIN" # Ensure PATH is updated in current shell
    print_success "Go $GO_VERSION_TARGET installed successfully on Linux."
}

install_go_macos() {
    print_info "Installing Go $GO_VERSION_TARGET for macOS..."
    curl -LO "https://go.dev/dl/go${GO_VERSION_TARGET}.darwin-amd64.pkg" || print_error "Failed to download Go for macOS."
    sudo installer -pkg "go${GO_VERSION_TARGET}.darwin-amd64.pkg" -target / || print_error "Failed to install Go package on macOS."
    rm "go${GO_VERSION_TARGET}.darwin-amd64.pkg"
    export PATH="$PATH:/usr/local/go/bin" # Ensure PATH is updated in current shell
    print_success "Go $GO_VERSION_TARGET installed successfully on macOS."
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

check_go_version() {
    local version
    version=$(go version 2>&1 | awk '{print $3}' | sed 's/go//') # Redirect stderr to stdout for error handling
    if [[ "$version" == *"error"* ]]; then # Check for "error" string in output
        print_warning "Failed to get Go version. Assuming Go is outdated or not properly installed. Attempting to install Go $GO_VERSION_TARGET."
        install_go # Attempt reinstall if version check fails
        return
    fi

    if [[ $(printf '%s\n' "$GO_VERSION_REQUIRED" "$version" | sort -V | head -n1) != "$GO_VERSION_REQUIRED" ]]; then
        print_warning "Go version $version is older than required $GO_VERSION_REQUIRED. Attempting to install Go $GO_VERSION_TARGET."
        install_go # Attempt reinstall if version is too old
    else
        print_info "Go version $version meets requirements ($GO_VERSION_REQUIRED or newer)."
    fi
}

install_go() {
    OS=$(uname -s)
    if [ "$OS" == "Linux" ]; then
        install_go_linux
    elif [ "$OS" == "Darwin" ]; then
        install_go_macos
    else
        print_error "Unsupported OS: $OS"
    fi
    check_go_version # Re-check version after install to confirm success
}


# --- Main Script Execution ---

print_info "Starting setup for caddy-waf..."

ensure_go_installed
ensure_xcaddy_installed
clone_or_update_repo
update_dependencies
download_geolite2_db
build_caddy
format_caddyfile
run_caddy

print_success "caddy-waf setup completed!"