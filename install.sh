#!/bin/bash
# Builds ProxyGate and installs it into /Applications.
#   ./install.sh              build + install + launch
#   ./install.sh --uninstall  remove the app, the privileged helper and settings prompt
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="ProxyGate.app"
DEST_DIR="/Applications"
[ -w "$DEST_DIR" ] || DEST_DIR="$HOME/Applications"
DEST="$DEST_DIR/$APP_NAME"

quit_running() {
    if pgrep -xq ProxyGate; then
        echo "→ Quitting running ProxyGate"
        osascript -e 'tell application id "com.proxygate.app" to quit' >/dev/null 2>&1 || true
        sleep 1
        pkill -x ProxyGate 2>/dev/null || true
    fi
}

if [ "${1:-}" = "--uninstall" ]; then
    quit_running
    if [ -f /Library/LaunchDaemons/com.proxygate.engine.plist ]; then
        echo "→ Removing privileged helper (administrator password required)"
        sudo launchctl bootout system/com.proxygate.engine 2>/dev/null || true
        sudo /sbin/pfctl -a com.apple/proxygate -F rules 2>/dev/null || true
        sudo /sbin/pfctl -a com.apple/proxygate -F nat 2>/dev/null || true
        sudo rm -f /Library/LaunchDaemons/com.proxygate.engine.plist \
                   /Library/PrivilegedHelperTools/com.proxygate.engine \
                   /var/run/com.proxygate.engine.sock
    fi
    for dir in /Applications "$HOME/Applications"; do
        [ -d "$dir/$APP_NAME" ] && rm -rf "${dir:?}/$APP_NAME" && echo "→ Removed $dir/$APP_NAME"
    done
    echo "Profiles kept in ~/Library/Application Support/ProxyGate (delete manually if not needed)."
    exit 0
fi

command -v swift >/dev/null || { echo "Swift toolchain not found: install Xcode or the Command Line Tools" >&2; exit 1; }

echo "→ Building"
./scripts/build-app.sh

quit_running
mkdir -p "$DEST_DIR"
echo "→ Installing to $DEST"
rm -rf "$DEST"
cp -R "build/$APP_NAME" "$DEST"

echo "→ Launching"
open "$DEST"
echo "Done. On first run click “Install Helper” (or “Update Helper” after an upgrade)."
