#!/bin/sh
# Courier installer: downloads the client binary for this platform from
# GitHub releases and verifies its SHA-256 checksum before installing.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/black-candle-technologies/courier/main/install.sh | sh
#
# Environment:
#   COURIER_VERSION  release tag to install (default: newest release that
#                    ships a binary for this platform)
#   COURIER_DEST     install path (default: $HOME/.local/bin/courier)
#
# Trust note: the SHA256SUMS file comes from the same release as the binary,
# so verification proves the download arrived intact — not that the release
# itself is authentic. If you don't trust the release channel, build from
# source instead.
set -e

REPO="black-candle-technologies/courier"

# --- helpers --------------------------------------------------------------

# fetch URL DEST: download URL to DEST with curl or wget, whichever exists.
fetch() {
	_f_url="$1"
	_f_dest="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 "$_f_url" -o "$_f_dest"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$_f_dest" "$_f_url"
	else
		echo "error: need curl or wget to download Courier" >&2
		return 1
	fi
}

# sha256_of FILE: print the hex SHA-256 digest of FILE.
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "error: need sha256sum or shasum to verify the download" >&2
		return 1
	fi
}

# sums_lookup SUMS_FILE ASSET: print the expected hex digest for ASSET from
# a SHA256SUMS-format file. Handles both text ("  ") and binary (" *")
# separators emitted by sha256sum.
sums_lookup() {
	_s_sums="$1"
	_s_asset="$2"
	awk -v name="$_s_asset" '
		{ n = $2; sub(/^\*/, "", n); if (n == name) { print $1; exit } }
	' "$_s_sums"
}

# verify_checksum SUMS_FILE ASSET FILE: check FILE's SHA-256 digest against
# the entry for ASSET in SUMS_FILE. Prints a clear error and returns 1 on
# any failure (missing entry, missing digest tool, or mismatch).
verify_checksum() {
	_v_sums="$1"
	_v_asset="$2"
	_v_file="$3"
	_want="$(sums_lookup "$_v_sums" "$_v_asset")"
	if [ -z "$_want" ]; then
		echo "error: no checksum for ${_v_asset} in SHA256SUMS; refusing to install" >&2
		return 1
	fi
	_got="$(sha256_of "$_v_file")" || return 1
	# Compare case-insensitively; digests are lowercase hex by convention.
	_want="$(printf '%s' "$_want" | tr 'A-Z' 'a-z')"
	_got="$(printf '%s' "$_got" | tr 'A-Z' 'a-z')"
	if [ "$_got" != "$_want" ]; then
		echo "error: SHA-256 mismatch for ${_v_asset}:" >&2
		echo "  expected: ${_want}" >&2
		echo "  actual:   ${_got}" >&2
		echo "The download may be corrupted or tampered with. Nothing was installed." >&2
		return 1
	fi
}

# pick_version_for_asset ASSET: read a GitHub releases API response on
# stdin and print the tag_name of the newest release whose assets include
# ASSET. Prints nothing when no release ships ASSET.
pick_version_for_asset() {
	_p_asset="$1"
	awk -v asset="$_p_asset" '
		/"tag_name"[[:space:]]*:/ {
			line = $0
			sub(/.*"tag_name"[[:space:]]*:[[:space:]]*"/, "", line)
			sub(/".*/, "", line)
			tag = line; in_assets = 0
			next
		}
		/"assets"[[:space:]]*:[[:space:]]*\[/ { in_assets = 1; next }
		in_assets && $0 ~ "\"name\"[[:space:]]*:[[:space:]]*\"" asset "\"" {
			print tag
			exit
		}
	'
}

# resolve_version OS ARCH: print the newest release tag that ships a
# courier-OS-ARCH binary, via the GitHub releases API.
resolve_version() {
	_r_os="$1"
	_r_arch="$2"
	_r_asset="courier-${_r_os}-${_r_arch}"
	_r_json="$(mktemp)" || return 1
	if fetch "https://api.github.com/repos/${REPO}/releases?per_page=50" "$_r_json"; then
		_r_tag="$(pick_version_for_asset "$_r_asset" < "$_r_json")"
	else
		_r_tag=""
	fi
	rm -f "$_r_json"
	[ -n "$_r_tag" ] || return 1
	printf '%s\n' "$_r_tag"
}

# --- main -----------------------------------------------------------------

main() {
	OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
	ARCH="$(uname -m)"
	case "$ARCH" in
		x86_64) ARCH="amd64" ;;
		aarch64|arm64) ARCH="arm64" ;;
		*) echo "error: unsupported arch: $ARCH" >&2; exit 1 ;;
	esac
	case "$OS" in
		linux|darwin) ;;
		*) echo "error: unsupported OS: $OS" >&2; exit 1 ;;
	esac

	VERSION="${COURIER_VERSION:-}"
	if [ -z "$VERSION" ]; then
		echo "resolving latest Courier release for ${OS}/${ARCH}..."
		if ! VERSION="$(resolve_version "$OS" "$ARCH")"; then
			echo "error: could not determine the latest Courier release." >&2
			echo "The GitHub API may be unreachable or rate-limited; install a" >&2
			echo "specific release instead, e.g.:" >&2
			echo "  COURIER_VERSION=v0.11.0 sh install.sh" >&2
			exit 1
		fi
		echo "latest release with a ${OS}/${ARCH} binary: ${VERSION}"
	fi

	ASSET="courier-${OS}-${ARCH}"
	BASE="https://github.com/${REPO}/releases/download/${VERSION}"
	DEST="${COURIER_DEST:-$HOME/.local/bin/courier}"

	echo "downloading courier ${VERSION} for ${OS}/${ARCH}..."
	mkdir -p "$(dirname "$DEST")"
	# Download to temp files first: nothing lands at $DEST until the
	# checksum verifies.
	TMPBIN="$(mktemp "$(dirname "$DEST")/.courier-install-XXXXXX")" || exit 1
	TMPSUMS="$(mktemp)" || { rm -f "$TMPBIN"; exit 1; }
	trap 'rm -f "$TMPBIN" "$TMPSUMS"' EXIT INT TERM
	if ! fetch "${BASE}/${ASSET}" "$TMPBIN"; then
		echo "error: failed to download ${BASE}/${ASSET}" >&2
		exit 1
	fi
	if ! fetch "${BASE}/SHA256SUMS" "$TMPSUMS"; then
		echo "error: failed to download ${BASE}/SHA256SUMS;" >&2
		echo "refusing to install an unverified binary." >&2
		exit 1
	fi
	if ! verify_checksum "$TMPSUMS" "$ASSET" "$TMPBIN"; then
		# verify_checksum already printed the reason.
		exit 1
	fi
	echo "checksum OK (${ASSET})"
	chmod +x "$TMPBIN"
	# Atomic publish: the temp file lives in the destination directory, so
	# rename(2) cannot cross filesystems.
	mv "$TMPBIN" "$DEST"
	trap - EXIT INT TERM
	rm -f "$TMPSUMS"

	echo "installed to $DEST"
	"$DEST" version
	case ":$PATH:" in
		*":$(dirname "$DEST"):"*) ;;
		*) echo "note: $(dirname "$DEST") is not on your PATH" ;;
	esac
	echo "next: courier init"
}

# Sourcing this file (INSTALL_SH_TEST=1) loads the helpers without running
# the installer, so install_test.sh can exercise the verification logic.
if [ "${INSTALL_SH_TEST:-}" != "1" ]; then
	main "$@"
fi
