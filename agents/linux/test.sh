#!/bin/sh
# Tests for chimera-agent.sh: parser on a saved `ss` output and the SQLite insert. No root, no Linux needed.
set -eu
cd "$(dirname "$0")"
fail() { echo "FAIL: $*" >&2; exit 1; }
out="$(sh chimera-agent.sh --from fixtures/ss-sample.txt --print --ts 1000 --host lab)"

[ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = 5 ] || fail "expected 5 rows"
printf '%s\n' "$out" | grep -qP '^1000\tlab\t4242\tupdater\t6\t192.168.1.10\t51234\t203.0.113.9\t443$' 2>/dev/null \
  || printf '%s\n' "$out" | grep -q "$(printf '1000\tlab\t4242\tupdater\t6\t192.168.1.10\t51234\t203.0.113.9\t443')" || fail "updater row"
printf '%s\n' "$out" | grep -q "$(printf '\t7001\tcurl\t6\t2001:db8::10\t41000\t2001:db8::99\t443')" || fail "ipv6 row"
printf '%s\n' "$out" | grep -q "$(printf '\t0\t-\t6\t192.168.1.10\t22\t')" || fail "row without a process must get pid 0 and name -"
printf '%s\n' "$out" | grep -q "'" && fail "a quote survived in the output"
printf '%s\n' "$out" | grep -q ';' && fail "a semicolon survived in the output"

# the database path
db="$(mktemp -d)/t.db"
sh chimera-agent.sh --from fixtures/ss-sample.txt --db "$db" --ts 1000 --host lab >/dev/null
[ "$(sqlite3 "$db" 'SELECT count(*) FROM host_connections')" = 5 ] || fail "row count in db"
[ "$(sqlite3 "$db" "SELECT process FROM host_connections WHERE raddr='203.0.113.9'")" = updater ] || fail "process in db"
[ "$(sqlite3 "$db" "SELECT name FROM sqlite_master WHERE name='x'")" = "" ] || fail "injection created a table"
# a second snapshot appends
sh chimera-agent.sh --from fixtures/ss-sample.txt --db "$db" --ts 1060 --host lab >/dev/null
[ "$(sqlite3 "$db" 'SELECT count(*) FROM host_connections')" = 10 ] || fail "second snapshot should append"

# bad arguments
sh chimera-agent.sh --print --ts abc 2>/dev/null && fail "non numeric --ts accepted"
sh chimera-agent.sh 2>/dev/null && fail "no output mode accepted"
echo "agent tests passed"
