package detect

import (
	"fmt"
	"sort"

	"github.com/rephuren/chimera/analyzer/store"
)

const (
	minFanOut     = 100 // distinct (destination, port) pairs from one source
	minPortSpread = 25  // distinct ports on a single destination
)

// FanOut finds sources that touch an unusually large number of destinations or ports: scanning, worms, or misconfigured tools.
func FanOut(flows []store.Flow) []Finding {
	pairs := map[string]map[string]bool{}
	ports := map[string]map[string]map[int]bool{}
	for _, f := range flows {
		if pairs[f.Src] == nil {
			pairs[f.Src] = map[string]bool{}
			ports[f.Src] = map[string]map[int]bool{}
		}
		pairs[f.Src][fmt.Sprintf("%s:%d", f.Dst, f.DPort)] = true
		if ports[f.Src][f.Dst] == nil {
			ports[f.Src][f.Dst] = map[int]bool{}
		}
		ports[f.Src][f.Dst][f.DPort] = true
	}
	var out []Finding
	for src, p := range pairs {
		if len(p) >= minFanOut {
			out = append(out, Finding{Kind: "fan-out", Severity: Medium, Subject: src, Src: src,
				Detail: fmt.Sprintf("%s contacted %d distinct destination/port pairs", src, len(p))})
		}
		for dst, set := range ports[src] {
			if len(set) >= minPortSpread {
				out = append(out, Finding{Kind: "port-spread", Severity: Medium, Subject: dst, Src: src,
					Detail: fmt.Sprintf("%s tried %d different ports on %s: looks like a port scan", src, len(set), dst)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Kind+out[i].Src+out[i].Subject < out[j].Kind+out[j].Src+out[j].Subject
	})
	return out
}
