#!/bin/bash
# Builds build/ProxyGate.app (GUI + bundled privileged engine).
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="${CONFIG:-release}"
swift build -c "$CONFIG" --product ProxyGate
swift build -c "$CONFIG" --product proxygate-engine
BIN="$(swift build -c "$CONFIG" --show-bin-path)"
VERSION="$(grep 'static let version' Sources/PGCore/Protocol.swift | sed -E 's/.*"(.*)".*/\1/')"

APP=build/ProxyGate.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/ProxyGate" "$APP/Contents/MacOS/ProxyGate"
cp "$BIN/proxygate-engine" "$APP/Contents/Resources/proxygate-engine"
cp -R Resources/*.lproj "$APP/Contents/Resources/"

# App icon, rendered from the same drawing code as the menu bar icon.
ICON_TMP="$(mktemp -d)"
cp scripts/make-icon.swift "$ICON_TMP/main.swift"
swiftc -O "$ICON_TMP/main.swift" Sources/ProxyGate/GateIcon.swift -o "$ICON_TMP/make-icon"
"$ICON_TMP/make-icon" "$ICON_TMP/AppIcon.iconset"
iconutil -c icns "$ICON_TMP/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$ICON_TMP"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>ProxyGate</string>
    <key>CFBundleDisplayName</key><string>ProxyGate</string>
    <key>CFBundleIdentifier</key><string>com.proxygate.app</string>
    <key>CFBundleExecutable</key><string>ProxyGate</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleLocalizations</key><array><string>en</string><string>ru</string></array>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key><string>ProxyGate connects to proxy servers on your local network.</string>
</dict>
</plist>
EOF

IDENTITY="${SIGN_IDENTITY:--}"
codesign --force --options runtime --sign "$IDENTITY" "$APP/Contents/Resources/proxygate-engine"
codesign --force --options runtime --sign "$IDENTITY" "$APP"
echo "Built $APP ($VERSION)"
