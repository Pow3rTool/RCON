#!/usr/bin/env bash
set -euo pipefail
RCON_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$RCON_ROOT"
RCON_VERSION="${1:?usage: build-windows-package.sh <version>}"
export GO="${GO:-$(command -v go || echo /usr/local/go/bin/go)}"
RCON_OUTPUT="${RCON_BUILD_DIR:-$RCON_ROOT/dist}"
"$RCON_ROOT/build.sh" "$RCON_VERSION" windows/amd64
RCON_STAGE="$(mktemp -d)"
# All generated staging files are retained in the task-specific temp directory.
cp "$RCON_OUTPUT/rcon-windows-amd64.exe" "$RCON_STAGE/rcon.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO" test -trimpath -c -o "$RCON_STAGE/rcon-tests.exe" "$RCON_ROOT"
cp "$RCON_ROOT/windows/Install-RCON.ps1" "$RCON_ROOT/windows/Test-RCON.ps1" "$RCON_ROOT/WINDOWS.md" "$RCON_STAGE/"
(
  cd "$RCON_STAGE"
  sha256sum rcon.exe rcon-tests.exe Install-RCON.ps1 Test-RCON.ps1 WINDOWS.md > SHA256SUMS.txt
  python3 -m zipfile -c "$RCON_OUTPUT/rcon-windows-amd64-$RCON_VERSION.zip" rcon.exe rcon-tests.exe Install-RCON.ps1 Test-RCON.ps1 WINDOWS.md SHA256SUMS.txt
)
sha256sum "$RCON_OUTPUT/rcon-windows-amd64-$RCON_VERSION.zip"
echo "Staging files: $RCON_STAGE"
