#!/bin/sh
# Builds the fuzz harnesses for wyrm (https://github.com/rephuren/wyrm). Needs clang and a built wyrm checkout.
#   WYRM=../wyrm sh core/fuzz/build.sh   ->   core/fuzz/build/fuzz_{dns,tls,decode,pcap}
set -eu
cd "$(dirname "$0")/.."
WYRM=${WYRM:-../../wyrm}
[ -x "$WYRM/build/wyrm" ] || { echo "wyrm not built at $WYRM (run make there)" >&2; exit 1; }
mkdir -p fuzz/build build
awk 'BEGIN{print "static const char SCHEMA[] ="} {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); print "\"" $0 "\\n\""} END{print ";"}' ../sql/schema.sql > build/schema_sql.h
SAN="-O0 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fsanitize-coverage=trace-pc-guard"
for h in dns tls decode pcap; do
    clang -std=c11 $SAN -Iinclude -Ibuild src/pcap.c src/decode.c src/dns.c src/tls.c src/store.c src/ingest.c fuzz/fuzz_$h.c \
        -c 2>&1 | grep -v "^$" || true
    # link everything through clang++ because wyrm's runtime is C++
    clang++ $SAN pcap.o decode.o dns.o tls.o store.o ingest.o fuzz_$h.o "$WYRM/build/coverage_rt.o" "$WYRM/build/persistent_rt.o" -lsqlite3 -o fuzz/build/fuzz_$h
    rm -f pcap.o decode.o dns.o tls.o store.o ingest.o fuzz_$h.o
done
echo "built: $(ls fuzz/build | tr '\n' ' ')"
