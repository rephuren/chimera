#!/bin/sh
# End to end: synthetic capture -> C core -> SQLite -> Go analyzer. Fails if the beacon or the generated name is not reported.
set -eu
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
make -C core >/dev/null
python3 scripts/make_demo_pcap.py "$tmp/demo.pcap"
core/build/chimera-core read "$tmp/demo.pcap" --db "$tmp/events.db"
# host agent: replay a saved `ss` snapshot once a minute while the capture runs (demo timestamps start at 1700000000)
for t in 1700000060 1700000120 1700000180 1700000240 1700000300 1700000360 1700000420 1700000480 1700000540 1700000600 1700000660 1700000720; do
    sh agents/linux/chimera-agent.sh --from agents/linux/fixtures/ss-sample.txt --db "$tmp/events.db" --ts "$t" --host lab >/dev/null
done
mkdir -p build
go build -o build/chimera-analyze ./analyzer/cmd/chimera-analyze
build/chimera-analyze report --db "$tmp/events.db" | tee "$tmp/report.txt"
grep -q "beacon" "$tmp/report.txt"
grep -q "update.cdn-example.test" "$tmp/report.txt"
grep -q "dns-high-entropy" "$tmp/report.txt"
grep -q "updater pid 4242" "$tmp/report.txt"
echo "e2e ok"
