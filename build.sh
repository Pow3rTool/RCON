#!/usr/bin/env bash
# Build the RCON agent — STATIC, cross-platform, with version + release pubkey
# baked in, and a GUARD that fails the build if the pubkey didn't actually land
# (the keyless-binary bug that bit us: a binary with no baked pubkey can't verify
# self-updates, so it silently bricks the update path).
#
#   ./build.sh v0.3.0                 # build dist/rcon-linux-{amd64,arm64}
#   ./build.sh v0.3.0 linux/amd64     # just one platform
#   RCON_RELEASE_PUBKEY=… ./build.sh  # override the pinned key
#
# The release public key is read from $RCON_RELEASE_PUBKEY, else release-pubkey.txt
# (regenerate that file with: orthanc `manage.py export_release_pubkey`).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
VERSION="${1:?usage: build.sh <version> [os/arch ...]}"
shift || true
PLATFORMS=("$@"); [ ${#PLATFORMS[@]} -eq 0 ] && PLATFORMS=(linux/amd64 linux/arm64)
GO="${GO:-$(command -v go || echo /usr/local/go/bin/go)}"
OUT="${RCON_BUILD_DIR:-$HERE/dist}"

PUBKEY="${RCON_RELEASE_PUBKEY:-$(cat "$HERE/release-pubkey.txt" 2>/dev/null || true)}"
if [ -z "$PUBKEY" ]; then
  echo "FATAL: no release pubkey (set RCON_RELEASE_PUBKEY or create release-pubkey.txt)" >&2
  exit 1
fi
[ -x "$GO" ] || { echo "FATAL: Go toolchain not found ($GO) — build on a host that has it" >&2; exit 1; }

mkdir -p "$OUT"
echo "rcon $VERSION  ·  pubkey ${PUBKEY:0:12}…  ·  $GO ($($GO version | awk '{print $3}'))"
for plat in "${PLATFORMS[@]}"; do
  os="${plat%/*}"; arch="${plat#*/}"
  out="$OUT/rcon-$os-$arch"
  case "$os" in
    windows) out="$out.exe" ;;
    linux) ;;
    *) echo "FATAL: unsupported OS: $os (supported: linux, windows)" >&2; exit 1 ;;
  esac
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$GO" build \
    -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.releasePubKeyB64=$PUBKEY" \
    -o "$out" "$HERE"

  # GUARD 1: the pubkey MUST be baked in, or self-update can't verify -> brick.
  if ! grep -qa "$PUBKEY" "$out"; then
    echo "FATAL: release pubkey NOT baked into $out — refusing to ship" >&2
    rm -f "$out"; exit 1
  fi
  # GUARD 2: must be static (no libc dependency on the target).
  if file "$out" | grep -q "dynamically linked"; then
    echo "FATAL: $out is dynamically linked — set CGO_ENABLED=0" >&2
    rm -f "$out"; exit 1
  fi
  printf "  ✓ %s  (%s bytes, CGO disabled, pubkey verified)\n" "$out" "$(stat -c %s "$out")"
done

echo
echo "Artifacts ready. Linux: publish/sign/promote on the control plane (see BUILD.md)."
echo "Windows lab: manual installation/upgrades only; see WINDOWS.md. Do not promote to Linux channels."
