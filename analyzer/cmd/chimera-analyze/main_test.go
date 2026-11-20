package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/rephuren/chimera/analyzer/detect"
	"github.com/rephuren/chimera/analyzer/web"
)

// makeDB builds a database from the real schema file, so a schema change that breaks the analyzer breaks this test.
func makeDB(t *testing.T) string {
	t.Helper()
	schema, err := os.ReadFile("../../../sql/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for i := 0; i < 8; i++ {
		_, err = db.Exec("INSERT INTO tls_events(ts,src,sport,dst,dport,version,sni) VALUES(?,?,?,?,?,?,?)", 1000+i*30, "10.0.0.5", 50000+i, "203.0.113.9", 443, 771, "c2.example.test")
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.Exec("INSERT INTO dns_events(ts,src,dst,is_response,rcode,qname,qtype,answers) VALUES(900,'8.8.8.8','10.0.0.5',1,0,'c2.example.test',1,'1=203.0.113.9')")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO host_connections(ts,host,pid,process,proto,laddr,lport,raddr,rport) VALUES(1000,'h1',777,'updater',6,'10.0.0.5',50000,'203.0.113.9',443)")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReportTextAndJSON(t *testing.T) {
	path := makeDB(t)
	var out, errb bytes.Buffer
	if code := run([]string{"report", "--db", path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "beacon") || !strings.Contains(out.String(), "updater pid 777") {
		t.Errorf("text report lacks the beacon or its process:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"report", "--db", path, "--json", "--min", "medium"}, &out, &errb); code != 0 {
		t.Fatal("json exit", code)
	}
	var rep detect.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Summary.TLSEvents != 8 || len(rep.Findings) == 0 {
		t.Errorf("bad json report: %v %s", err, out.String())
	}
}

func TestErrorsAndRemoteGuard(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, &out, &errb) != 2 || run([]string{"report"}, &out, &errb) != 2 {
		t.Error("usage errors must exit 2")
	}
	if run([]string{"report", "--db", filepath.Join(t.TempDir(), "missing.db")}, &out, &errb) != 1 {
		t.Error("missing database must exit 1")
	}
	if run([]string{"serve", "--db", makeDB(t), "--addr", "0.0.0.0:0"}, &out, &errb) != 2 || !strings.Contains(errb.String(), "allow-remote") {
		t.Error("listening on all interfaces must need --allow-remote")
	}
}

func TestHTTPHandler(t *testing.T) {
	path := makeDB(t)
	h := web.Handler(func() (detect.Report, error) { return analyze(path) })
	srv := httptest.NewServer(h)
	defer srv.Close()
	for _, p := range []string{"/", "/api/summary", "/api/findings?min=medium", "/healthz"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, resp)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("%s: no CSP header", p)
		}
		resp.Body.Close()
	}
	resp, _ := http.Post(srv.URL+"/", "text/plain", strings.NewReader("x"))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST must be refused, got %d", resp.StatusCode)
	}
	resp, _ = http.Get(srv.URL + "/nope")
	if resp.StatusCode != 404 {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
}

func TestHTMLEscapesHostileNames(t *testing.T) {
	h := web.Handler(func() (detect.Report, error) {
		return detect.Report{Findings: []detect.Finding{{Kind: "x", Severity: detect.Medium, Subject: "<script>alert(1)</script>", Detail: "\"><img src=x onerror=alert(1)>"}}}, nil
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/")
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if strings.Contains(buf.String(), "<script>alert") || strings.Contains(buf.String(), "<img src=x") {
		t.Errorf("unescaped output: %s", buf.String())
	}
}

func TestLoopbackDetection(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:80": true, "localhost:80": true, "[::1]:80": true, "0.0.0.0:80": false, ":80": false, "192.168.1.5:80": false, "bad": false} {
		if got := web.IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v", addr, got)
		}
	}
}
