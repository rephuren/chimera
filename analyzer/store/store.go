// Package store reads the SQLite database written by the C core and the host agents. It never writes.
package store

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo
)

type Answer struct {
	Type int
	Data string
}

type DNSEvent struct {
	TS         int64
	Src, Dst   string
	IsResponse bool
	RCode      int
	QName      string
	QType      int
	Answers    []Answer
}

type TLSEvent struct {
	TS           int64
	Src, Dst     string
	SPort, DPort int
	Version      int
	SNI          string
}

type Flow struct {
	Proto           int
	Src, Dst        string
	SPort, DPort    int
	FirstTS, LastTS int64
	Packets, Bytes  int64
}

type HostConn struct {
	TS            int64
	Host, Process string
	PID, Proto    int
	LAddr, RAddr  string
	LPort, RPort  int
}

type DB struct{ db *sql.DB }

// Open opens the database read-only.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(3000)")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db}, nil
}

func (d *DB) Close() error { return d.db.Close() }

func (d *DB) hasTable(name string) bool {
	var n int
	_ = d.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0
}

// ParseAnswers parses the "type=data;type=data" text the core writes.
func ParseAnswers(s string) []Answer {
	var out []Answer
	for _, part := range strings.Split(s, ";") {
		t, data, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(t)
		if err != nil {
			continue
		}
		out = append(out, Answer{n, data})
	}
	return out
}

func (d *DB) DNS() ([]DNSEvent, error) {
	rows, err := d.db.Query("SELECT ts,src,dst,is_response,rcode,qname,qtype,answers FROM dns_events ORDER BY ts, id")
	if err != nil {
		return nil, fmt.Errorf("dns_events: %w", err)
	}
	defer rows.Close()
	var out []DNSEvent
	for rows.Next() {
		var e DNSEvent
		var resp int
		var ans string
		if err := rows.Scan(&e.TS, &e.Src, &e.Dst, &resp, &e.RCode, &e.QName, &e.QType, &ans); err != nil {
			return nil, err
		}
		e.IsResponse = resp != 0
		e.Answers = ParseAnswers(ans)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) TLS() ([]TLSEvent, error) {
	rows, err := d.db.Query("SELECT ts,src,sport,dst,dport,version,sni FROM tls_events ORDER BY ts, id")
	if err != nil {
		return nil, fmt.Errorf("tls_events: %w", err)
	}
	defer rows.Close()
	var out []TLSEvent
	for rows.Next() {
		var e TLSEvent
		if err := rows.Scan(&e.TS, &e.Src, &e.SPort, &e.Dst, &e.DPort, &e.Version, &e.SNI); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) Flows() ([]Flow, error) {
	rows, err := d.db.Query("SELECT proto,src,sport,dst,dport,first_ts,last_ts,packets,bytes FROM flows ORDER BY first_ts, id")
	if err != nil {
		return nil, fmt.Errorf("flows: %w", err)
	}
	defer rows.Close()
	var out []Flow
	for rows.Next() {
		var f Flow
		if err := rows.Scan(&f.Proto, &f.Src, &f.SPort, &f.Dst, &f.DPort, &f.FirstTS, &f.LastTS, &f.Packets, &f.Bytes); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// HostConns returns the connections reported by host agents; an empty slice when no agent has written anything.
func (d *DB) HostConns() ([]HostConn, error) {
	if !d.hasTable("host_connections") {
		return nil, nil
	}
	rows, err := d.db.Query("SELECT ts,host,pid,process,proto,laddr,lport,raddr,rport FROM host_connections ORDER BY ts, id")
	if err != nil {
		return nil, fmt.Errorf("host_connections: %w", err)
	}
	defer rows.Close()
	var out []HostConn
	for rows.Next() {
		var c HostConn
		if err := rows.Scan(&c.TS, &c.Host, &c.PID, &c.Process, &c.Proto, &c.LAddr, &c.LPort, &c.RAddr, &c.RPort); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
