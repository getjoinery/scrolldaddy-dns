#!/usr/bin/env bash
#version 1.0 - Initial deploy script for ScrollDaddy DNS server
#
# Deploys the scrolldaddy-dns Go binary to the DNS server.
# Uses git sparse checkout to fetch only public_html/scrolldaddy-dns/,
# builds the binary on the server, and restarts the systemd service.
#
# Usage:
#   deploy_dns.sh [--verbose]
#
# Can be run:
#   - Directly on the DNS server: ./deploy.sh
#   - Remotely via SSH: ssh root@45.56.103.84 'bash -s' < scrolldaddy-dns/deploy.sh
#
# DNS Server:
#   IP: 45.56.103.84 | SSH key: ~/.ssh/id_ed25519_claude
#   Binary: /usr/local/bin/scrolldaddy-dns (systemd: scrolldaddy-dns)
#   Logs: /var/log/scrolldaddy/dns.log
#   Internal API (localhost:8053): /reload (POST), /stats (GET), /test (GET) — require X-API-Key header

DEPLOY_VERSION="1.0"
SERVICE_NAME="scrolldaddy-dns"
BINARY_PATH="/usr/local/bin/scrolldaddy-dns"
STAGE_DIR="/tmp/scrolldaddy-dns-deploy"
STATS_URL="http://localhost:8053/stats"

# GitHub credentials (same as deploy.sh)
GITHUB_USER="getjoinery"
GITHUB_TOKEN="REDACTED_TOKEN"
REPO_URL="https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/getjoinery/joinery.git"

# Parse arguments
VERBOSE=false
for arg in "$@"; do
    case $arg in
        --verbose) VERBOSE=true ;;
    esac
done

verbose_echo() {
    if [ "$VERBOSE" = true ]; then
        echo "$@"
    fi
}

echo "========================================="
echo "ScrollDaddy DNS Deploy v${DEPLOY_VERSION}"
echo "========================================="

# Verify prerequisites
echo "Checking prerequisites..."
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed."
    exit 1
fi
if ! command -v git &> /dev/null; then
    echo "ERROR: git is not installed."
    exit 1
fi
if ! systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo "WARNING: $SERVICE_NAME service is not currently running."
fi
verbose_echo "  Go: $(go version)"
verbose_echo "  Git: $(git --version)"

# Clean staging directory
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Sparse checkout: only fetch scrolldaddy-dns source
echo "Fetching source from git (sparse checkout)..."
if [ "$VERBOSE" = true ]; then
    git clone --no-checkout "$REPO_URL" "$STAGE_DIR/repo"
else
    git clone --quiet --no-checkout "$REPO_URL" "$STAGE_DIR/repo" 2>/dev/null
fi

if [ $? -ne 0 ]; then
    echo "ERROR: git clone failed."
    rm -rf "$STAGE_DIR"
    exit 1
fi

cd "$STAGE_DIR/repo" || exit 1
git config core.sparseCheckout true
git sparse-checkout init --cone
git sparse-checkout set public_html/scrolldaddy-dns

if [ "$VERBOSE" = true ]; then
    git checkout main
else
    git checkout --quiet main 2>/dev/null
fi

if [ ! -d "public_html/scrolldaddy-dns" ]; then
    echo "ERROR: scrolldaddy-dns source not found after checkout."
    rm -rf "$STAGE_DIR"
    exit 1
fi

# Move source to build directory
mv public_html/scrolldaddy-dns "$STAGE_DIR/build"
rm -rf "$STAGE_DIR/repo"
echo "  Source fetched successfully."

# Build the binary
echo "Building binary..."
cd "$STAGE_DIR/build" || exit 1
if [ "$VERBOSE" = true ]; then
    go build -o "$STAGE_DIR/scrolldaddy-dns" ./cmd/dns
else
    go build -o "$STAGE_DIR/scrolldaddy-dns" ./cmd/dns 2>&1
fi

if [ $? -ne 0 ]; then
    echo "ERROR: Go build failed."
    rm -rf "$STAGE_DIR"
    exit 1
fi
echo "  Build successful."

# Deploy: stop service, swap binary, start service
echo "Deploying binary..."
if [ -f "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" "${BINARY_PATH}.bak"
    verbose_echo "  Backed up current binary to ${BINARY_PATH}.bak"
fi

systemctl stop "$SERVICE_NAME"
cp "$STAGE_DIR/scrolldaddy-dns" "$BINARY_PATH"
chmod 755 "$BINARY_PATH"
systemctl start "$SERVICE_NAME"

# Wait for service to start and load data
echo "Waiting for service to start..."
sleep 5

# Verify
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "  Service is running."
else
    echo "ERROR: Service failed to start. Check: journalctl -u $SERVICE_NAME"
    echo "Rolling back to previous binary..."
    if [ -f "${BINARY_PATH}.bak" ]; then
        cp "${BINARY_PATH}.bak" "$BINARY_PATH"
        systemctl start "$SERVICE_NAME"
        echo "  Rollback complete."
    fi
    rm -rf "$STAGE_DIR"
    exit 1
fi

# Check stats endpoint
STATS=$(curl -s --connect-timeout 5 "$STATS_URL" 2>/dev/null)
if [ -n "$STATS" ]; then
    echo "  Stats: $STATS"
else
    echo "  WARNING: Could not reach stats endpoint."
fi

# Cleanup
rm -rf "$STAGE_DIR"
rm -f "${BINARY_PATH}.bak"

echo "========================================="
echo "SUCCESS: DNS server deployed."
echo "========================================="
