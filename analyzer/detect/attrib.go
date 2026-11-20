package detect

import (
	"fmt"
	"strings"

	"github.com/rephuren/chimera/analyzer/store"
)

const attribWindow = 120 // seconds between a network event and the host agent's snapshot of the connection

func near(a, b int64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= attribWindow
}

// Attribute fills in the process for findings whose subject is a remote address the host agent also saw a connection to.
func Attribute(findings []Finding, hosts []store.HostConn) {
	for i := range findings {
		f := &findings[i]
		if f.TS == 0 || f.Src == "" {
			continue
		}
		for _, h := range hosts {
			if h.LAddr == f.Src && near(h.TS, f.TS) && (h.RAddr == f.Subject || containsAddr(f.Detail, h.RAddr)) {
				f.Process, f.PID = h.Process, h.PID
				break
			}
		}
	}
}

func containsAddr(detail, addr string) bool { return addr != "" && strings.Contains(detail, addr) }

// Unattributed finds TLS connections from a host that has an agent, with no matching connection in the agent's data.
// That is a gap worth looking at: traffic the host did not report (agent missed it, or the process hid it).
func Unattributed(tls []store.TLSEvent, hosts []store.HostConn) []Finding {
	if len(hosts) == 0 {
		return nil
	}
	monitored := map[string]bool{}
	for _, h := range hosts {
		monitored[h.LAddr] = true
	}
	var out []Finding
	seen := map[string]bool{}
	for _, e := range tls {
		if !monitored[e.Src] {
			continue
		}
		matched := false
		for _, h := range hosts {
			if h.LAddr == e.Src && h.RAddr == e.Dst && h.RPort == e.DPort && near(h.TS, e.TS) {
				matched = true
				break
			}
		}
		k := fmt.Sprintf("%s|%s|%d", e.Src, e.Dst, e.DPort)
		if !matched && !seen[k] {
			seen[k] = true
			out = append(out, Finding{Kind: "unattributed-connection", Severity: Medium, Subject: e.Dst, Src: e.Src, TS: e.TS,
				Detail: fmt.Sprintf("%s connected to %s:%d (SNI %q) but its host agent reported no such connection within %d s", e.Src, e.Dst, e.DPort, e.SNI, attribWindow)})
		}
	}
	return out
}
