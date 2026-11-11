#!/bin/bash
# Build only. Never install/register/enable filters, modify routes, or touch SIP.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${NETGUARD_ARCH:-arm64}"
case "$ARCH" in arm64|x86_64) ;; *) echo 'Unsupported architecture' >&2; exit 2;; esac
[[ "$(uname -s)" == Darwin ]] || { echo 'A macOS SDK host is required; no cross-platform success claim.' >&2; exit 2; }
OUT="${NETGUARD_BUILD_DIR:-$ROOT/build}"
APP="$OUT/NetGuard.app"
GENERATED="$OUT/generated"
mkdir -p "$GENERATED"
python3 "$ROOT/scripts/generate-metadata.py" --output "$GENERATED" --team-id "${NETGUARD_TEAM_ID:-}" --app-group "${NETGUARD_APP_GROUP:-}"
xcrun swift build --package-path "$ROOT/NetGuardCore" -c release --arch "$ARCH"
CORE="$(xcrun swift build --package-path "$ROOT/NetGuardCore" -c release --arch "$ARCH" --show-bin-path)"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
PLATFORM=("$ROOT/Platform/"*.swift)
[[ -f "${PLATFORM[0]}" ]] || { echo 'Platform implementation missing' >&2; exit 3; }
COMMON=(-swift-version 5 -parse-as-library -target "$ARCH-apple-macosx15.0" -sdk "$SDK" -I "$CORE/Modules" -L "$CORE" -lNetGuardCore)
FRAMEWORKS=(-framework Foundation -framework AppKit -framework Network -framework NetworkExtension -framework Security -framework SystemExtensions -framework ServiceManagement)
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchServices" "$APP/Contents/Library/LaunchDaemons"
cp "$GENERATED/App-Info.plist" "$APP/Contents/Info.plist"
cp "$GENERATED/BUILD-STATUS.txt" "$APP/Contents/Resources/BUILD-STATUS.txt"
cp "$GENERATED/Helper-LaunchDaemon.plist" "$APP/Contents/Library/LaunchDaemons/app.netguard.macos.helper.plist"
xcrun swiftc "${COMMON[@]}" -module-name NetGuardApp "${PLATFORM[@]}" "$GENERATED/BuildIdentity.swift" "$ROOT/App/"*.swift "${FRAMEWORKS[@]}" -framework SwiftUI -o "$APP/Contents/MacOS/NetGuard"
xcrun swiftc "${COMMON[@]}" -module-name NetGuardHelper "${PLATFORM[@]}" "$GENERATED/BuildIdentity.swift" "$ROOT/Helper/"*.swift "${FRAMEWORKS[@]}" -o "$APP/Contents/Library/LaunchServices/NetGuardHelper"
for role in socket packet; do
  if [[ "$role" == socket ]]; then FOLDER=SocketFilter; EXE=NetGuardSocket; else FOLDER=PacketFilter; EXE=NetGuardPacket; fi
  BUNDLE="$APP/Contents/Library/SystemExtensions/app.netguard.macos.$role.systemextension"
  mkdir -p "$BUNDLE/Contents/MacOS"
  cp "$GENERATED/$role-Info.plist" "$BUNDLE/Contents/Info.plist"
  xcrun swiftc "${COMMON[@]}" -module-name "$EXE" "${PLATFORM[@]}" "$GENERATED/BuildIdentity.swift" "$ROOT/Extensions/$FOLDER/"*.swift "${FRAMEWORKS[@]}" -o "$BUNDLE/Contents/MacOS/$EXE"
done
python3 "$ROOT/scripts/verify-bundle.py" "$APP" --architecture "$ARCH"
echo "Unsigned development bundle: $APP"
echo 'Signing, local approvals and real-machine security acceptance are still required.'
