#!/bin/sh
# End to end: synthetic capture -> C core -> SQLite -> Go analyzer. Fails if the beacon or the generated name is not reported.
set -eu
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
make -C core >/dev/null
python3 scripts/make_demo_pcap.py "$tmp/demo.pcap"
core/build/chimera-core read "$tmp/demo.pcap" --db "$tmp/events.db"
mkdir -p build
go build -o build/chimera-analyze ./analyzer/cmd/chimera-analyze
build/chimera-analyze report --db "$tmp/events.db" | tee "$tmp/report.txt"
grep -q "beacon" "$tmp/report.txt"
grep -q "update.cdn-example.test" "$tmp/report.txt"
grep -q "dns-high-entropy" "$tmp/report.txt"
echo "e2e ok"
