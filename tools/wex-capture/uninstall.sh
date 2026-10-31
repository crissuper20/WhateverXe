#!/bin/bash
# Run with sudo to remove the service. Captures in /Users/Shared/wex-capture are kept.
launchctl bootout system/com.local.wex-capture 2>/dev/null
rm -f /Library/LaunchDaemons/com.local.wex-capture.plist
rm -rf '/Library/Application Support/wex-capture'
echo 'Capture service removed.'
