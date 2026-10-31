#!/bin/bash
# Run once: sudo bash ~/wex-capture/install.sh
set -e
[ "$(id -u)" = 0 ] || { echo 'Run this with sudo.'; exit 1; }
H=$(cd "$(dirname "$0")" && pwd)
mkdir -p '/Library/Application Support/wex-capture' /Users/Shared/wex-capture
install -m 755 "$H/capture.sh" '/Library/Application Support/wex-capture/capture.sh'
install -m 644 -o root -g wheel "$H/com.local.wex-capture.plist" /Library/LaunchDaemons/com.local.wex-capture.plist
launchctl bootstrap system /Library/LaunchDaemons/com.local.wex-capture.plist 2>/dev/null || true
launchctl print system/com.local.wex-capture >/dev/null && echo 'Capture service installed.'
