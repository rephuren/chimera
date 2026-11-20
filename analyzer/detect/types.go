// Package detect turns stored network and host events into findings. All detectors are heuristics: a finding is a lead, not a verdict.
package detect

import (
	"sort"

	"github.com/rephuren/chimera/analyzer/store"
)

type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
	Info   Severity = "info"
)

var rank = map[Severity]int{High: 0, Medium: 1, Low: 2, Info: 3}

// AtLeast reports whether s is as severe as or more severe than min.
func (s Severity) AtLeast(min Severity) bool { return rank[s] <= rank[min] }

type Finding struct {
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"`
	Src      string   `json:"src,omitempty"`
	Detail   string   `json:"detail"`
	TS       int64    `json:"ts,omitempty"`
	Process  string   `json:"process,omitempty"`
	PID      int      `json:"pid,omitempty"`
}

type Input struct {
	DNS   []store.DNSEvent
	TLS   []store.TLSEvent
	Flows []store.Flow
	Hosts []store.HostConn
}

type Summary struct {
	Flows, DNSEvents, TLSEvents, HostConns int
	FirstTS, LastTS                        int64
}

type Report struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

// Analyze runs every detector and returns findings ordered by severity, then time.
func Analyze(in Input) Report {
	var f []Finding
	f = append(f, DNSAnomalies(in.DNS)...)
	f = append(f, Beacons(in.TLS)...)
	f = append(f, SNIMismatch(in.DNS, in.TLS)...)
	f = append(f, FanOut(in.Flows)...)
	f = append(f, Unattributed(in.TLS, in.Hosts)...)
	Attribute(f, in.Hosts)
	sort.SliceStable(f, func(i, j int) bool {
		if rank[f[i].Severity] != rank[f[j].Severity] {
			return rank[f[i].Severity] < rank[f[j].Severity]
		}
		return f[i].TS < f[j].TS
	})
	r := Report{Findings: f}
	r.Summary = summarize(in)
	return r
}

func summarize(in Input) Summary {
	s := Summary{Flows: len(in.Flows), DNSEvents: len(in.DNS), TLSEvents: len(in.TLS), HostConns: len(in.Hosts)}
	see := func(ts int64) {
		if s.FirstTS == 0 || ts < s.FirstTS {
			s.FirstTS = ts
		}
		if ts > s.LastTS {
			s.LastTS = ts
		}
	}
	for _, e := range in.DNS {
		see(e.TS)
	}
	for _, e := range in.TLS {
		see(e.TS)
	}
	for _, f := range in.Flows {
		see(f.FirstTS)
		see(f.LastTS)
	}
	return s
}
