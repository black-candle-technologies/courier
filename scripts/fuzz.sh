#!/bin/sh
# Bounded fuzz run for the Courier fuzz targets (issue #112).
#
# Usage: ./scripts/fuzz.sh [fuzztime]   (default 30s per target)
#
# Each target gets FUZZTIME of mutation on top of its seed corpus.
# New crashers are written to the package's testdata/fuzz corpus and
# should be kept: `go test ./...` replays them as regression tests.
# The CI workflow (issue #106) should invoke this script on a schedule
# (e.g. nightly) rather than on every PR, since fuzzing is
# time-consuming.
set -eu

FUZZTIME="${1:-30s}"
# Local dev shells may not have Go on PATH (CI is expected to provide it).
if ! command -v go >/dev/null 2>&1; then
	export PATH="/home/hatch/workspace/go-toolkit/go/bin:$PATH"
fi

run() {
	pkg="$1"; target="$2"
	echo "=== fuzzing $target ($pkg, ${FUZZTIME}) ==="
	(
		cd "$(dirname "$0")/.."
		go test "./$pkg" -run="^$" -fuzz="^${target}$" -fuzztime="$FUZZTIME"
	)
}

run internal/crypto FuzzParseAddress
run internal/crypto FuzzEd25519PubToX25519
run internal/crypto FuzzBackupPayloadValidate
run internal/crypto FuzzOpenBackup
run internal/envelope FuzzParseGroupID
run internal/envelope FuzzNormalizeHandle
run internal/envelope FuzzValidateCapabilities
run internal/envelope FuzzValidateManifest
run internal/client FuzzParseFSPayload
run internal/client FuzzFSSkippedCounter
run internal/relay FuzzHandleSend
run internal/relay FuzzHandleGroupControl
run internal/store FuzzMigrateOldSchemaDB
run internal/store FuzzEscapeLike
run internal/store FuzzSearchThreadPeers
run internal/dashboard FuzzLoginForm
run internal/bridge FuzzHandleIngest

echo "=== all fuzz targets completed ==="
