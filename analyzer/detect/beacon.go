package detect

import (
	"fmt"
	"math"
	"sort"

	"github.com/rephuren/chimera/analyzer/store"
)

const (
	minBeaconEvents = 6
	maxJitter       = 0.15 // coefficient of variation of the intervals
	minPeriod       = 5.0  // seconds; faster than this is ordinary polling or noise
	maxPeriod       = 3600.0
)

// Beacons finds clients that open TLS connections to the same destination at suspiciously regular intervals.
// Regularity alone proves nothing (update checks and keepalives look the same), so findings are medium at most.
func Beacons(events []store.TLSEvent) []Finding {
	type key struct{ src, dst, sni string }
	groups := map[key][]int64{}
	for _, e := range events {
		k := key{e.Src, e.Dst, e.SNI}
		groups[k] = append(groups[k], e.TS)
	}
	var out []Finding
	for k, ts := range groups {
		if len(ts) < minBeaconEvents {
			continue
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		var gaps []float64
		for i := 1; i < len(ts); i++ {
			gaps = append(gaps, float64(ts[i]-ts[i-1]))
		}
		mean, sd := meanStd(gaps)
		if mean < minPeriod || mean > maxPeriod || mean == 0 {
			continue
		}
		cv := sd / mean
		if cv > maxJitter {
			continue
		}
		subject := k.sni
		if subject == "" {
			subject = k.dst
		}
		out = append(out, Finding{Kind: "beacon", Severity: Medium, Subject: subject, Src: k.src, TS: ts[0],
			Detail: fmt.Sprintf("%d connections from %s to %s every %.0f s (jitter %.0f%%): regular, like automated check-ins", len(ts), k.src, k.dst, mean, cv*100)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject+out[i].Src < out[j].Subject+out[j].Src })
	return out
}

func meanStd(v []float64) (float64, float64) {
	if len(v) == 0 {
		return 0, 0
	}
	m := 0.0
	for _, x := range v {
		m += x
	}
	m /= float64(len(v))
	s := 0.0
	for _, x := range v {
		s += (x - m) * (x - m)
	}
	return m, math.Sqrt(s / float64(len(v)))
}
