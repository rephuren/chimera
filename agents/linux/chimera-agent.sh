#!/bin/sh
# chimera host agent for Linux: records which process holds which established TCP connection, so the analyzer can name the
# process behind a network finding. Read-only: it runs `ss` and writes rows into the chimera SQLite database.
#
#   chimera-agent.sh --db events.db            snapshot now and insert into host_connections
#   chimera-agent.sh --print                   print the rows as tab separated text, touch no database
#   chimera-agent.sh --from FILE --print       parse saved `ss -H -tnp state established` output (used by the tests)
#   --ts EPOCH   timestamp to record instead of the current time (for replays)
#   --host NAME  host name to record instead of `hostname`
#
# Without root `ss` only shows the processes of the current user; the other connections get pid 0 and process "-".
# Not covered: UDP, listening sockets, short-lived connections that start and end between two snapshots.
set -eu

db="" ; from="" ; print=0 ; ts="" ; host=""
while [ $# -gt 0 ]; do
    case "$1" in
        --db) db="${2:?--db needs a file}"; shift 2 ;;
        --from) from="${2:?--from needs a file}"; shift 2 ;;
        --print) print=1; shift ;;
        --ts) ts="${2:?--ts needs a number}"; shift 2 ;;
        --host) host="${2:?--host needs a name}"; shift 2 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$db" ] || [ "$print" -eq 1 ] || { echo "give --db FILE or --print" >&2; exit 2; }
case "$ts" in ""|*[!0-9]*) [ -z "$ts" ] || { echo "--ts must be a number" >&2; exit 2; } ;; esac
[ -n "$ts" ] || ts="$(date +%s)"
[ -n "$host" ] || host="$(hostname)"
# the host name ends up in a SQL string: keep only harmless characters
host="$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)"

# `ss -H -tnp state established` lines look like:
#   0 0 10.0.0.5:50000 203.0.113.9:443 users:(("curl",pid=1234,fd=3))
#   0 0 [2001:db8::1]:41000 [2001:db8::2]:443 users:(("sshd",pid=7,fd=4))
# Output: ts, host, pid, process, proto, laddr, lport, raddr, rport (tab separated, process name sanitized).
parse() {
    awk -v ts="$ts" -v host="$host" '
    function split_addr(s,    i, a, p) {
        sub(/^\[/, "", s)
        i = match(s, /:[0-9]+$/)
        if (!i) return 0
        p = substr(s, i + 1); a = substr(s, 1, i - 1); sub(/\]$/, "", a)
        ADDR = a; PORT = p
        return 1
    }
    NF >= 4 {
        if (!split_addr($3)) next; la = ADDR; lp = PORT
        if (!split_addr($4)) next; ra = ADDR; rp = PORT
        pid = 0; name = "-"
        if (match($0, /\(\("[^"]*",pid=[0-9]+/)) {
            seg = substr($0, RSTART, RLENGTH)
            sub(/^\(\("/, "", seg)
            n = index(seg, "\",pid=")
            name = substr(seg, 1, n - 1); pid = substr(seg, n + 6) + 0
        }
        gsub(/[^A-Za-z0-9_.+:@\/-]/, "_", name); name = substr(name, 1, 64)
        if (name == "") name = "-"
        if (la !~ /^[0-9A-Fa-f:.]+$/ || ra !~ /^[0-9A-Fa-f:.]+$/) next
        printf "%s\t%s\t%d\t%s\t6\t%s\t%d\t%s\t%d\n", ts, host, pid, name, la, lp, ra, rp
    }'
}

if [ -n "$from" ]; then
    rows="$(parse < "$from")"
else
    command -v ss >/dev/null 2>&1 || { echo "ss not found (iproute2 is required)" >&2; exit 1; }
    rows="$(ss -H -tnp state established | parse)"
fi

if [ "$print" -eq 1 ]; then
    [ -z "$rows" ] || printf '%s\n' "$rows"
    exit 0
fi

command -v sqlite3 >/dev/null 2>&1 || { echo "sqlite3 not found" >&2; exit 1; }
{
    echo "CREATE TABLE IF NOT EXISTS host_connections (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, host TEXT NOT NULL, pid INTEGER NOT NULL, process TEXT NOT NULL, proto INTEGER NOT NULL, laddr TEXT NOT NULL, lport INTEGER NOT NULL, raddr TEXT NOT NULL, rport INTEGER NOT NULL);"
    echo "CREATE INDEX IF NOT EXISTS hostconn_remote ON host_connections(raddr, rport);"
    echo "CREATE INDEX IF NOT EXISTS hostconn_time ON host_connections(ts);"
    echo "BEGIN;"
    printf '%s\n' "$rows" | awk -F'\t' 'NF == 9 { printf "INSERT INTO host_connections(ts,host,pid,process,proto,laddr,lport,raddr,rport) VALUES(%d,\047%s\047,%d,\047%s\047,%d,\047%s\047,%d,\047%s\047,%d);\n", $1, $2, $3, $4, $5, $6, $7, $8, $9 }'
    echo "COMMIT;"
} | sqlite3 "$db"
echo "recorded $(printf '%s' "$rows" | grep -c . || true) connection(s) into $db"
