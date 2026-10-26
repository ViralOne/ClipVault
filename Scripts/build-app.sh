#!/usr/bin/env bash
# Builds dist/ClipVault.app, signed with the hardened runtime and the App
# Sandbox entitlements.
#
# Signing identity, in order of precedence:
#   1. CODESIGN_IDENTITY environment variable
#   2. the first line of .signing-identity in the repository root (gitignored)
#   3. ad-hoc ("-")
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${1:-release}"
APP="$ROOT/dist/ClipVault.app"
ENTITLEMENTS="$ROOT/Support/ClipVault.entitlements"

cd "$ROOT"
swift build -c "$CONFIG" --product ClipVault
BIN_DIR="$(swift build -c "$CONFIG" --show-bin-path)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/ClipVault" "$APP/Contents/MacOS/ClipVault"
cp "$ROOT/Support/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/Support/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

IDENTITY="${CODESIGN_IDENTITY:-}"
if [[ -z "$IDENTITY" && -f "$ROOT/.signing-identity" ]]; then
    IDENTITY="$(head -n 1 "$ROOT/.signing-identity")"
fi
IDENTITY="${IDENTITY:--}"

TIMESTAMP="--timestamp=none"
if [[ "${CODESIGN_TIMESTAMP:-0}" == "1" ]]; then
    TIMESTAMP="--timestamp"
fi

codesign --force --options runtime $TIMESTAMP \
    --entitlements "$ENTITLEMENTS" \
    --sign "$IDENTITY" "$APP"
codesign --verify --strict --verbose=1 "$APP"

if [[ "$IDENTITY" == "-" ]]; then
    echo "Signed ad-hoc. Set CODESIGN_IDENTITY or create .signing-identity for a stable signature."
else
    echo "Signed with a local identity (hardened runtime, App Sandbox)."
fi
echo "Built $APP"
