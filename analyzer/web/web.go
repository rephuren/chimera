// Package web serves the analysis over a small local HTTP API and one HTML page. It is read-only.
package web

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"time"

	"github.com/rephuren/chimera/analyzer/detect"
)

// Analyze produces a fresh report; the server calls it per request so the page reflects the database as it grows.
type Analyze func() (detect.Report, error)

var page = template.Must(template.New("p").Funcs(template.FuncMap{
	"ts": func(t int64) string {
		if t == 0 {
			return ""
		}
		return time.Unix(t, 0).UTC().Format("2006-01-02 15:04:05")
	},
}).Parse(`<!doctype html><meta charset="utf-8"><title>chimera</title>
<style>body{background:#050505;color:#e8e8e8;font:14px/1.5 Menlo,Consolas,monospace;margin:2rem}h1{letter-spacing:.3em}
.k{color:#8a8a8a}.high,.medium{color:#b3000f}table{border-collapse:collapse}td,th{padding:.2rem .8rem;text-align:left;border-bottom:1px solid #2a2a2a;vertical-align:top}</style>
<h1>CHIMERA</h1>
<p class="k">flows {{.Summary.Flows}} · dns {{.Summary.DNSEvents}} · tls {{.Summary.TLSEvents}} · host connections {{.Summary.HostConns}} · {{ts .Summary.FirstTS}} to {{ts .Summary.LastTS}} UTC</p>
{{if .Findings}}<table><tr><th>sev</th><th>kind</th><th>src</th><th>subject</th><th>process</th><th>detail</th></tr>
{{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td>{{.Kind}}</td><td>{{.Src}}</td><td>{{.Subject}}</td><td>{{.Process}}</td><td>{{.Detail}}</td></tr>{{end}}</table>
{{else}}<p>no findings</p>{{end}}
<p class="k">Findings are leads from heuristics, not verdicts.</p>`))

func security(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Handler builds the HTTP handler: /, /api/summary, /api/findings, /healthz.
func Handler(run Analyze) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("/api/summary", func(w http.ResponseWriter, r *http.Request) {
		rep, err := run()
		if err != nil {
			http.Error(w, "analysis failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep.Summary)
	})
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		rep, err := run()
		if err != nil {
			http.Error(w, "analysis failed", http.StatusInternalServerError)
			return
		}
		min := detect.Severity(r.URL.Query().Get("min"))
		out := rep.Findings[:0:0]
		for _, f := range rep.Findings {
			if min == "" || f.Severity.AtLeast(min) {
				out = append(out, f)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		rep, err := run()
		if err != nil {
			http.Error(w, "analysis failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, rep)
	})
	return security(mux)
}

// IsLoopback reports whether addr (host:port) binds only to the local machine.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
