#!/usr/bin/env sh
# Install a prebuilt aya-app release from GitHub.
#
# Usage:
#   ./scripts/install.sh                 # latest release, ~/.local/bin
#   VERSION=v0.1.0 ./scripts/install.sh
#   PREFIX=/usr/local ./scripts/install.sh   # may require sudo
#
# The script verifies the SHA256SUMS entry for `aya-app` before installing.
# It supports x86_64 Linux only; build from source on other architectures.
set -eu

REPO="zhangmingze1913/aya-app"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-$HOME/.local}"

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) ;;
    *)
        echo "unsupported platform: $(uname -s) $(uname -m); see docs/architectures.md" >&2
        exit 1
        ;;
esac

if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    case "$VERSION" in
        v*) TAG="$VERSION" ;;
        *) TAG="v$VERSION" ;;
    esac
    BASE="https://github.com/$REPO/releases/download/$TAG"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fetch() {
    url="$1"
    out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --max-time 180 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url"
    else
        echo "curl or wget is required" >&2
        exit 1
    fi
}

echo "==> downloading $VERSION from $REPO"
fetch "$BASE/aya-app" "$TMP/aya-app"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"

EXPECTED="$(awk '$2 == "aya-app" { print $1 }' "$TMP/SHA256SUMS")"
if [ -z "$EXPECTED" ]; then
    echo "SHA256SUMS has no aya-app entry" >&2
    exit 1
fi
ACTUAL="$(sha256sum "$TMP/aya-app" | awk '{ print $1 }')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "checksum mismatch: expected $EXPECTED, got $ACTUAL" >&2
    exit 1
fi

mkdir -p "$PREFIX/bin"
install -m 0755 "$TMP/aya-app" "$PREFIX/bin/aya-app"
echo "==> installed $PREFIX/bin/aya-app"
"$PREFIX/bin/aya-app" --version || true
