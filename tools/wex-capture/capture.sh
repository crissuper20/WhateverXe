#!/bin/bash
# Saves WhateverXe evidence each boot, because registry records die at shutdown
# and the next boot overwrites the Lilu log. Reads only.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
ROOT=${WEX_CAPTURE_ROOT:-/Users/Shared/wex-capture}
DELAYS=${WEX_CAPTURE_DELAYS:-"120 240 480"} # Seconds of uptime. Lilu dumps its log at 120.
OUT="$ROOT/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$OUT" || exit 1
uptime_s() { local b; b=$(sysctl -n kern.boottime | sed -E 's/.*\{ sec = ([0-9]+).*/\1/'); echo $(( $(date +%s)-b )); }
snap() {
 local d="$OUT/t$1"; mkdir -p "$d"
 ioreg -lw0 -d1 2>/dev/null | grep -E '"(TGL|N97|WEX|XELP|ADLP)[A-Za-z0-9_]*"' | sed -E 's/^ +//' > "$d/root-flags.txt"
 ioreg -r -n IGPU@2 -d1 -l -w0 2>/dev/null | grep -E '"(TGL|N97|WEX|XELP|ADLP)[A-Za-z0-9_]*"' | sed -E 's/^ +//' > "$d/igpu-flags.txt"
 ioreg -p IOService -w0 -r -n IGPU@2 -d 3 2>/dev/null | cut -c1-110 > "$d/igpu-tree.txt"
 cp /var/log/Lilu_*.txt "$d/" 2>/dev/null
 /usr/bin/log show --last 15m --style compact --predicate 'process == "kernel"' 2>/dev/null \
  | grep -E '\[IGFB\]|\[IGPU\]|AppleIntelTGL|IOAccelDisplayPipe|AppleBacklight' | grep -v BRINGUP > "$d/driver-log.txt"
 sysctl -n kern.boottime > "$d/boottime.txt"; sync
}
for t in $DELAYS; do
 now=$(uptime_s); [ "$now" -lt "$t" ] && sleep $(( t-now ))
 snap "$t"
done
ls -1d "$ROOT"/*/ 2>/dev/null | sort -r | tail -n +9 | while read -r old; do rm -rf "$old"; done
