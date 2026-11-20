-- chimera storage. Times are Unix seconds with a nanosecond part kept separately only where needed.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1');

-- one row per directional 5-tuple
CREATE TABLE IF NOT EXISTS flows (
    id       INTEGER PRIMARY KEY,
    proto    INTEGER NOT NULL,
    src      TEXT NOT NULL,
    sport    INTEGER NOT NULL,
    dst      TEXT NOT NULL,
    dport    INTEGER NOT NULL,
    first_ts INTEGER NOT NULL,
    last_ts  INTEGER NOT NULL,
    packets  INTEGER NOT NULL,
    bytes    INTEGER NOT NULL,
    UNIQUE (proto, src, sport, dst, dport)
);
CREATE INDEX IF NOT EXISTS flows_dst ON flows(dst, dport);
CREATE INDEX IF NOT EXISTS flows_time ON flows(first_ts);

CREATE TABLE IF NOT EXISTS dns_events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    is_response INTEGER NOT NULL,
    rcode       INTEGER NOT NULL,
    qname       TEXT NOT NULL,
    qtype       INTEGER NOT NULL,
    answers     TEXT NOT NULL      -- "type=data;type=data", empty for queries
);
CREATE INDEX IF NOT EXISTS dns_qname ON dns_events(qname);
CREATE INDEX IF NOT EXISTS dns_time ON dns_events(ts);

CREATE TABLE IF NOT EXISTS tls_events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    src     TEXT NOT NULL,
    sport   INTEGER NOT NULL,
    dst     TEXT NOT NULL,
    dport   INTEGER NOT NULL,
    version INTEGER NOT NULL,
    sni     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tls_sni ON tls_events(sni);
CREATE INDEX IF NOT EXISTS tls_time ON tls_events(ts);

-- written by host agents; the analyzer joins it with flows and TLS events to attribute traffic to processes
CREATE TABLE IF NOT EXISTS host_connections (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    host    TEXT NOT NULL,
    pid     INTEGER NOT NULL,
    process TEXT NOT NULL,
    proto   INTEGER NOT NULL,
    laddr   TEXT NOT NULL,
    lport   INTEGER NOT NULL,
    raddr   TEXT NOT NULL,
    rport   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS hostconn_remote ON host_connections(raddr, rport);
CREATE INDEX IF NOT EXISTS hostconn_time ON host_connections(ts);
