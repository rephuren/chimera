package detect

import (
	"fmt"
	"math"
	"strings"

	"github.com/rephuren/chimera/analyzer/store"
)

const (
	minEntropyLen    = 15  // shorter labels do not carry enough symbols for entropy to mean anything
	entropyThreshold = 3.6 // bits per character; ordinary words sit around 2.5-3.2
	maxNameLen       = 80
	maxLabelLen      = 40
	minUniqueSubs    = 50
	minNXDomain      = 20
)

// Entropy returns the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	cnt := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		cnt[r]++
		n++
	}
	h := 0.0
	for _, c := range cnt {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// registered returns the last two labels. This is a deliberate simplification: there is no public suffix list, so
// "example.co.uk" is treated as "co.uk". Heuristics below tolerate that.
func registered(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// DNSAnomalies looks for names that resemble generated domains or DNS tunnelling.
func DNSAnomalies(events []store.DNSEvent) []Finding {
	var out []Finding
	subs := map[string]map[string]bool{} // "src|domain" -> distinct subdomain names
	nx := map[string]int{}               // client -> NXDOMAIN answers
	answers := map[string]int{}          // client -> all answers
	seen := map[string]bool{}
	for _, e := range events {
		if e.IsResponse {
			answers[e.Dst]++
			if e.RCode == 3 {
				nx[e.Dst]++
			}
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(e.QName, "."))
		dom := registered(name)
		key := e.Src + "|" + dom
		if subs[key] == nil {
			subs[key] = map[string]bool{}
		}
		subs[key][name] = true

		if seen[e.Src+"|"+name] {
			continue
		}
		seen[e.Src+"|"+name] = true
		labels := strings.Split(name, ".")
		longest := 0
		for _, l := range labels {
			if len(l) > longest {
				longest = len(l)
			}
		}
		if len(name) > maxNameLen || longest > maxLabelLen {
			out = append(out, Finding{Kind: "dns-long-name", Severity: Medium, Subject: name, Src: e.Src, TS: e.TS,
				Detail: fmt.Sprintf("name is %d characters, longest label %d: data may be encoded in the name (tunnelling)", len(name), longest)})
			continue
		}
		if len(labels) >= 2 {
			sld := labels[len(labels)-2]
			if len(sld) >= minEntropyLen && Entropy(sld) >= entropyThreshold {
				out = append(out, Finding{Kind: "dns-high-entropy", Severity: Medium, Subject: name, Src: e.Src, TS: e.TS,
					Detail: fmt.Sprintf("label %q has entropy %.2f bits/char: looks generated rather than chosen", sld, Entropy(sld))})
			}
		}
	}
	for key, names := range subs {
		if len(names) >= minUniqueSubs {
			src, dom, _ := strings.Cut(key, "|")
			out = append(out, Finding{Kind: "dns-many-subdomains", Severity: Medium, Subject: dom, Src: src,
				Detail: fmt.Sprintf("%d distinct names under %s: typical of tunnelling or generated domains", len(names), dom)})
		}
	}
	for client, n := range nx {
		if n >= minNXDomain && float64(n)/float64(answers[client]) >= 0.5 {
			out = append(out, Finding{Kind: "dns-nxdomain-rate", Severity: Medium, Subject: client, Src: client,
				Detail: fmt.Sprintf("%d of %d DNS answers were NXDOMAIN: possible domain generation algorithm", n, answers[client])})
		}
	}
	return out
}
