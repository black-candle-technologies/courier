#!/bin/sh
# Courier installer: downloads the right client binary from GitHub releases.
# Usage: curl -fsSL https://raw.githubusercontent.com/black-candle-technologies/courier/main/install.sh | sh
set -e

REPO="black-candle-technologies/courier"
VERSION="${COURIER_VERSION:-v0.8.0}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64)  ARCH="arm64" ;;
  arm64)    ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

URL="https://github.com/${REPO}/releases/download/${VERSION}/courier-${OS}-${ARCH}"
DEST="${COURIER_DEST:-$HOME/.local/bin/courier}"

echo "downloading courier ${VERSION} for ${OS}/${ARCH}..."
mkdir -p "$(dirname "$DEST")"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$DEST"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$DEST" "$URL"
else
  echo "need curl or wget" >&2; exit 1
fi
chmod +x "$DEST"

echo "installed to $DEST"
"$DEST" version
case ":$PATH:" in
  *":$(dirname "$DEST"):"*) ;;
  *) echo "note: $(dirname "$DEST") is not on your PATH" ;;
esac
echo "next: courier init"
