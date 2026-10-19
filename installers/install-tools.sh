#!/usr/bin/env bash
# installers/install-tools.sh — Linux/macOS version.
# Downloads the latest stable binaries for the popular free recon tools
# into ./bin/ (project-local, does NOT touch system PATH).
#
# Usage:  bash installers/install-tools.sh

set -euo pipefail
BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/bin"
mkdir -p "$BIN_DIR"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  darwin) GOOS="macos" ;;
  linux)  GOOS="linux" ;;
  *) echo "unsupported OS: $OS"; exit 1 ;;
esac
ARCH="amd64"

fetch_latest() {
  local owner="$1" repo="$2" pattern="$3"
  curl -fsSL "https://api.github.com/repos/$owner/$repo/releases/latest" \
    | grep "browser_download_url" \
    | grep -E "$pattern" \
    | head -1 | cut -d '"' -f 4
}

install_pd() {
  local name="$1" repo="$2" pattern="$3"
  echo "[$name] querying latest release..."
  local url
  url="$(fetch_latest projectdiscovery "$repo" "$pattern")"
  if [[ -z "$url" ]]; then echo "  no matching asset for $pattern"; return; fi
  local tmp="$BIN_DIR/_${name}_dl.zip"
  echo "  downloading $(basename "$url")"
  curl -fsSL "$url" -o "$tmp"
  unzip -oq "$tmp" -d "$BIN_DIR"
  rm -f "$tmp"
  chmod +x "$BIN_DIR/$name" 2>/dev/null || true
  echo "  installed -> $BIN_DIR/$name"
}

echo "=== offsec-mcp tool installer ($OS/$ARCH) ==="

install_pd subfinder subfinder  "subfinder_${OS}_${ARCH}\.zip$"      || true
install_pd httpx     httpx      "httpx_${OS}_${ARCH}\.zip$"          || true
install_pd dnsx      dnsx       "dnsx_${OS}_${ARCH}\.zip$"           || true
install_pd nuclei    nuclei     "nuclei_${OS}_${ARCH}\.zip$"         || true

# amass uses a different naming scheme
echo "[amass] querying latest release..."
AMASS_URL="$(fetch_latest owasp-amass amass "amass_${OS}_${ARCH}\.tar\.gz$")"
if [[ -n "$AMASS_URL" ]]; then
  curl -fsSL "$AMASS_URL" -o "$BIN_DIR/amass.tar.gz"
  tar -xzf "$BIN_DIR/amass.tar.gz" -C "$BIN_DIR"
  rm -f "$BIN_DIR/amass.tar.gz"
  chmod +x "$BIN_DIR/amass" 2>/dev/null || true
  echo "  installed -> $BIN_DIR/amass"
fi

echo "=== done ==="
echo "Binaries in: $BIN_DIR"

# Bootstrap nuclei community templates onto the same SSD as the binaries.
# Without this nuclei runs but exits 2 because it has nothing to check.
# Keeps the whole setup portable: nothing written to $HOME.
if [[ -x "$BIN_DIR/nuclei" ]]; then
  TMPL_DIR="$BIN_DIR/nuclei-templates"
  echo ""
  echo "[nuclei-templates] bootstrapping community template pack onto SSD..."
  echo "  destination: $TMPL_DIR"
  "$BIN_DIR/nuclei" -update-templates -ud "$TMPL_DIR" \
    && echo "  templates installed -> $TMPL_DIR" \
    || echo "  run manually: $BIN_DIR/nuclei -update-templates -ud $TMPL_DIR"
fi
