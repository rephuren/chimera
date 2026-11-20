package detect

import (
	"fmt"
	"strings"

	"github.com/rephuren/chimera/analyzer/store"
)

// SNIMismatch compares what the client asked for in TLS with what DNS told it. Both can be benign (DNS before the capture
// started, cached answers, DNS over HTTPS, CDNs), so these are leads.
func SNIMismatch(dns []store.DNSEvent, tls []store.TLSEvent) []Finding {
	if len(dns) == 0 {
		return nil // without any DNS in the capture there is nothing to compare against
	}
	byName := map[string]map[string]bool{} // name -> IPs it resolved to, following CNAME chains
	resolvedIP := map[string]bool{}
	for _, e := range dns {
		if !e.IsResponse {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(e.QName, "."))
		for _, a := range e.Answers {
			if a.Type == 1 || a.Type == 28 {
				if byName[name] == nil {
					byName[name] = map[string]bool{}
				}
				byName[name][a.Data] = true
				resolvedIP[a.Data] = true
			}
		}
	}
	var out []Finding
	seen := map[string]bool{}
	for _, e := range tls {
		k := e.Src + "|" + e.Dst + "|" + e.SNI
		if seen[k] {
			continue
		}
		seen[k] = true
		sni := strings.ToLower(e.SNI)
		switch {
		case sni == "" && !resolvedIP[e.Dst]:
			out = append(out, Finding{Kind: "tls-no-sni-unresolved", Severity: Medium, Subject: e.Dst, Src: e.Src, TS: e.TS,
				Detail: fmt.Sprintf("TLS to %s:%d with no server name, and no DNS answer in the capture pointed to that address", e.Dst, e.DPort)})
		case sni != "" && !resolvedIP[e.Dst]:
			out = append(out, Finding{Kind: "sni-ip-never-resolved", Severity: Low, Subject: e.SNI, Src: e.Src, TS: e.TS,
				Detail: fmt.Sprintf("%s asked for %q at %s, but no DNS answer in the capture gave that address (cached, DNS over HTTPS, or hard-coded?)", e.Src, e.SNI, e.Dst)})
		case sni != "" && len(byName[sni]) > 0 && !byName[sni][e.Dst]:
			out = append(out, Finding{Kind: "sni-ip-mismatch", Severity: Medium, Subject: e.SNI, Src: e.Src, TS: e.TS,
				Detail: fmt.Sprintf("%q resolved to a different address than the one contacted (%s); possible domain fronting or stale cache", e.SNI, e.Dst)})
		}
	}
	return out
}
