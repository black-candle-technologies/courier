#!/bin/sh
# Test harness for install.sh's download-verification logic.
# Uses local fixtures only: nothing is downloaded, nothing is installed,
# nothing is published.
#
# Run: sh install_test.sh
set -e
cd "$(dirname "$0")"

# Sourcing with INSTALL_SH_TEST=1 loads install.sh's helpers without
# running the installer itself.
INSTALL_SH_TEST=1
. ./install.sh

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT INT TERM

# --- fixtures -------------------------------------------------------------
printf 'fake-courier-binary-payload' > "$FIX/courier-linux-amd64"
SUM="$(sha256_of "$FIX/courier-linux-amd64")"
printf '%s  courier-linux-amd64\n' "$SUM" > "$FIX/SHA256SUMS"
# binary-mode marker variant (" *")
printf '%s *courier-darwin-arm64\n' "$SUM" > "$FIX/SHA256SUMS.bin"
# uppercase-hex variant
printf '%s  courier-linux-amd64\n' "$(printf '%s' "$SUM" | tr 'a-z' 'A-Z')" > "$FIX/SHA256SUMS.upper"

cat > "$FIX/releases.json" <<'EOF'
[
  {
    "tag_name": "v0.13.0",
    "name": "Courier v0.13.0",
    "assets": [
      { "name": "courier-dashboard-linux-amd64", "browser_download_url": "https://example.com/d" },
      { "name": "SHA256SUMS", "browser_download_url": "https://example.com/s" }
    ]
  },
  {
    "tag_name": "v0.11.0",
    "name": "v0.11.0",
    "assets": [
      { "name": "courier-linux-amd64", "browser_download_url": "https://example.com/a" },
      { "name": "SHA256SUMS", "browser_download_url": "https://example.com/s" }
    ]
  },
  {
    "tag_name": "v0.10.0",
    "name": "v0.10.0",
    "assets": [
      { "name": "courier-linux-amd64", "browser_download_url": "https://example.com/b" }
    ]
  }
]
EOF

# --- verify_checksum ------------------------------------------------------
if verify_checksum "$FIX/SHA256SUMS" "courier-linux-amd64" "$FIX/courier-linux-amd64" 2>/dev/null; then
	ok "verify_checksum accepts a matching download"
else
	bad "verify_checksum accepts a matching download"
fi

cp "$FIX/courier-linux-amd64" "$FIX/tampered"
printf 'X' >> "$FIX/tampered"
if verify_checksum "$FIX/SHA256SUMS" "courier-linux-amd64" "$FIX/tampered" 2>/dev/null; then
	bad "verify_checksum rejects a tampered download"
else
	ok "verify_checksum rejects a tampered download"
fi

if verify_checksum "$FIX/SHA256SUMS" "courier-windows-amd64.exe" "$FIX/courier-linux-amd64" 2>/dev/null; then
	bad "verify_checksum refuses when the asset is missing from SHA256SUMS"
else
	ok "verify_checksum refuses when the asset is missing from SHA256SUMS"
fi

if verify_checksum "$FIX/SHA256SUMS.bin" "courier-darwin-arm64" "$FIX/courier-linux-amd64" 2>/dev/null; then
	ok "verify_checksum handles the binary-mode (' *') sums format"
else
	bad "verify_checksum handles the binary-mode (' *') sums format"
fi

if verify_checksum "$FIX/SHA256SUMS.upper" "courier-linux-amd64" "$FIX/courier-linux-amd64" 2>/dev/null; then
	ok "verify_checksum compares digests case-insensitively"
else
	bad "verify_checksum compares digests case-insensitively"
fi

# --- sums_lookup ----------------------------------------------------------
if [ -z "$(sums_lookup "$FIX/SHA256SUMS" "no-such-asset")" ]; then
	ok "sums_lookup returns empty for an unknown asset"
else
	bad "sums_lookup returns empty for an unknown asset"
fi

# --- pick_version_for_asset -----------------------------------------------
GOT="$(pick_version_for_asset "courier-linux-amd64" < "$FIX/releases.json")"
if [ "$GOT" = "v0.11.0" ]; then
	ok "pick_version_for_asset skips newer releases lacking the asset (got $GOT)"
else
	bad "pick_version_for_asset skips newer releases lacking the asset (got '$GOT', want v0.11.0)"
fi

GOT="$(pick_version_for_asset "courier-dashboard-linux-amd64" < "$FIX/releases.json")"
if [ "$GOT" = "v0.13.0" ]; then
	ok "pick_version_for_asset finds dashboard-only assets (got $GOT)"
else
	bad "pick_version_for_asset finds dashboard-only assets (got '$GOT', want v0.13.0)"
fi

GOT="$(pick_version_for_asset "courier-plan9-amd64" < "$FIX/releases.json")"
if [ -z "$GOT" ]; then
	ok "pick_version_for_asset prints nothing when no release ships the asset"
else
	bad "pick_version_for_asset prints nothing when no release ships the asset (got '$GOT')"
fi

# --- fetch: curl/wget fallback paths --------------------------------------
# Stub downloaders that honor each tool's real argument shape, so the test
# proves fetch() drives them correctly without touching the network.
mkdir -p "$FIX/stubbin" "$FIX/empty"

cat > "$FIX/stubbin/curl" <<'EOF'
#!/bin/sh
# stub curl: curl -fsSL --proto ... --tlsv1.2 URL -o DEST
dest=""
prev=""
for a in "$@"; do
	if [ "$prev" = "-o" ]; then dest="$a"; fi
	prev="$a"
done
[ -n "$dest" ] || exit 2
printf 'stubbed-via-curl' > "$dest"
EOF
chmod +x "$FIX/stubbin/curl"

if PATH="$FIX/stubbin:$PATH" fetch "https://example.com/courier" "$FIX/dl-curl" \
	&& [ "$(cat "$FIX/dl-curl")" = "stubbed-via-curl" ]; then
	ok "fetch uses curl with -o DEST when curl is present"
else
	bad "fetch uses curl with -o DEST when curl is present"
fi

mkdir -p "$FIX/stubbin-wget"
cat > "$FIX/stubbin-wget/wget" <<'EOF'
#!/bin/sh
# stub wget: wget -qO DEST URL
dest=""
while [ $# -gt 0 ]; do
	case "$1" in
		-qO) dest="$2"; shift 2 ;;
		*) shift ;;
	esac
done
[ -n "$dest" ] || exit 2
printf 'stubbed-via-wget' > "$dest"
EOF
chmod +x "$FIX/stubbin-wget/wget"

if PATH="$FIX/stubbin-wget:$FIX/empty" fetch "https://example.com/courier" "$FIX/dl-wget" \
	&& [ "$(cat "$FIX/dl-wget")" = "stubbed-via-wget" ]; then
	ok "fetch falls back to wget -qO DEST when curl is absent"
else
	bad "fetch falls back to wget -qO DEST when curl is absent"
fi

# Neither downloader present: clear error, nonzero exit.
if PATH="$FIX/empty" fetch "https://example.com/courier" "$FIX/dl-none" 2>/dev/null; then
	bad "fetch fails clearly when neither curl nor wget exists"
else
	ok "fetch fails clearly when neither curl nor wget exists"
fi

# A failing downloader propagates the failure.
cat > "$FIX/stubbin/curl" <<'EOF'
#!/bin/sh
exit 1
EOF
if PATH="$FIX/stubbin:$PATH" fetch "https://example.com/courier" "$FIX/dl-fail" 2>/dev/null; then
	bad "fetch propagates a downloader failure"
else
	ok "fetch propagates a downloader failure"
fi

# --- summary --------------------------------------------------------------
echo "---"
echo "pass: $PASS, fail: $FAIL"
[ "$FAIL" -eq 0 ]
