// Command chimera-analyze reads a chimera database and reports suspicious network and host activity.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rephuren/chimera/analyzer/detect"
	"github.com/rephuren/chimera/analyzer/store"
	"github.com/rephuren/chimera/analyzer/web"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: chimera-analyze report --db FILE [--json] [--min high|medium|low|info]")
	fmt.Fprintln(w, "       chimera-analyze serve  --db FILE [--addr 127.0.0.1:8088] [--allow-remote]")
}

func analyze(path string) (detect.Report, error) {
	db, err := store.Open(path)
	if err != nil {
		return detect.Report{}, err
	}
	defer db.Close()
	var in detect.Input
	if in.DNS, err = db.DNS(); err != nil {
		return detect.Report{}, err
	}
	if in.TLS, err = db.TLS(); err != nil {
		return detect.Report{}, err
	}
	if in.Flows, err = db.Flows(); err != nil {
		return detect.Report{}, err
	}
	if in.Hosts, err = db.HostConns(); err != nil {
		return detect.Report{}, err
	}
	return detect.Analyze(in), nil
}

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 || (args[0] != "report" && args[0] != "serve") {
		usage(errw)
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(errw)
	dbPath := fs.String("db", "", "path to the chimera SQLite database")
	asJSON := fs.Bool("json", false, "JSON output (report)")
	min := fs.String("min", "low", "lowest severity to show: high, medium, low, info (report)")
	addr := fs.String("addr", "127.0.0.1:8088", "listen address (serve)")
	remote := fs.Bool("allow-remote", false, "allow listening on a non-loopback address (serve); the page has no authentication")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *dbPath == "" {
		usage(errw)
		return 2
	}
	if _, err := os.Stat(*dbPath); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if args[0] == "serve" {
		if !web.IsLoopback(*addr) && !*remote {
			fmt.Fprintln(errw, "error: refusing to listen on a non-loopback address without --allow-remote (the page has no authentication)")
			return 2
		}
		srv := &http.Server{Addr: *addr, Handler: web.Handler(func() (detect.Report, error) { return analyze(*dbPath) }),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}
		fmt.Fprintf(out, "listening on http://%s\n", *addr)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		return 0
	}
	rep, err := analyze(*dbPath)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	floor := detect.Severity(*min)
	var shown []detect.Finding
	for _, f := range rep.Findings {
		if f.Severity.AtLeast(floor) {
			shown = append(shown, f)
		}
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(detect.Report{Summary: rep.Summary, Findings: shown})
		return 0
	}
	s := rep.Summary
	fmt.Fprintf(out, "flows %d · dns %d · tls %d · host connections %d\n", s.Flows, s.DNSEvents, s.TLSEvents, s.HostConns)
	for _, f := range shown {
		proc := ""
		if f.Process != "" {
			proc = fmt.Sprintf(" [%s pid %d]", f.Process, f.PID)
		}
		fmt.Fprintf(out, "[%-6s] %-24s %s%s\n         %s\n", f.Severity, f.Kind, f.Subject, proc, f.Detail)
	}
	if len(shown) == 0 {
		fmt.Fprintln(out, "no findings at this level")
	}
	return 0
}
