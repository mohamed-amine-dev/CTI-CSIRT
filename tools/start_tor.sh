#!/usr/bin/env bash
# =============================================================================
# Tor launcher (rootless)
# -----------------------------------------------------------------------------
# Starts a local Tor SOCKS5 proxy on 127.0.0.1:9050 for the Dark Web collector
# (Tor .onion scraping). Requires NO root and NO system install:
#
#   * if the official Tor "expert bundle" is not cached under tools/tor-bundle,
#     it downloads the latest linux-x86_64 build from dist.torproject.org;
#   * then runs the `tor` daemon in the background (RunAsDaemon 1) with its
#     DataDirectory under tools/tor-data (both gitignored).
#
# Usage:
#   tools/start_tor.sh            # ensure Tor is running, download if needed
#
# Idempotent: exits 0 immediately when 127.0.0.1:9050 is already listening.
# =============================================================================
set -euo pipefail

PORT="${TOR_SOCKS_PORT:-9050}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_DIR="$ROOT/tools/tor-bundle"
DATA_DIR="$ROOT/tools/tor-data"
LOG_FILE="$ROOT/tools/tor.log"

if command -v tor >/dev/null 2>&1 && (ss -ltn 2>/dev/null | grep -q ":$PORT "); then
    echo "[tor] system tor already listening on $PORT"
    exit 0
fi
if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
    echo "[tor] something is already listening on $PORT"
    exit 0
fi

TOR_BIN=""
if command -v tor >/dev/null 2>&1; then
    TOR_BIN="$(command -v tor)"
elif [ -x "$BUNDLE_DIR/tor/tor" ]; then
    TOR_BIN="$BUNDLE_DIR/tor/tor"
else
    echo "[tor] downloading Tor expert bundle (rootless)"
    VERSION="$(curl -s https://dist.torproject.org/torbrowser/ | grep -oE 'href="[0-9]+\.[0-9]+\.[0-9]+/"' | sed -E 's/href="([0-9.]+)\/"/\1/' | sort -V | tail -1)"
    [ -n "$VERSION" ] || { echo "[tor] could not determine latest Tor version" >&2; exit 1; }
    mkdir -p "$BUNDLE_DIR"
    curl -sSL -o "$BUNDLE_DIR/tor-expert-bundle.tar.gz" \
        "https://dist.torproject.org/torbrowser/${VERSION}/tor-expert-bundle-linux-x86_64-${VERSION}.tar.gz"
    tar xzf "$BUNDLE_DIR/tor-expert-bundle.tar.gz" -C "$BUNDLE_DIR"
    rm -f "$BUNDLE_DIR/tor-expert-bundle.tar.gz"
    TOR_BIN="$BUNDLE_DIR/tor/tor"
fi

mkdir -p "$DATA_DIR"
echo "[tor] starting $TOR_BIN on 127.0.0.1:$PORT"
"$TOR_BIN" \
    --SocksPort "$PORT" \
    --DataDirectory "$DATA_DIR" \
    --Log "notice file $LOG_FILE" \
    --RunAsDaemon 1

for i in $(seq 1 30); do
    if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
        echo "[tor] listening on 127.0.0.1:$PORT"
        exit 0
    fi
    sleep 1
done
echo "[tor] failed to open $PORT (see $LOG_FILE)" >&2
exit 1
