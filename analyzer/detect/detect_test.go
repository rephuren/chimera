package detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rephuren/chimera/analyzer/store"
)

func kinds(f []Finding) map[string]int {
	m := map[string]int{}
	for _, x := range f {
		m[x.Kind]++
	}
	return m
}

func q(ts int64, src, name string) store.DNSEvent {
	return store.DNSEvent{TS: ts, Src: src, Dst: "8.8.8.8", QName: name, QType: 1}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaa") != 0 || Entropy("") != 0 {
		t.Error("constant strings have zero entropy")
	}
	if Entropy("google") >= entropyThreshold || Entropy("x7k2q9vz1m4p8d3w") < entropyThreshold {
		t.Errorf("thresholds do not separate words from random: %f %f", Entropy("google"), Entropy("x7k2q9vz1m4p8d3w"))
	}
}

func TestDNSHighEntropyAndLongNames(t *testing.T) {
	ev := []store.DNSEvent{
		q(1, "10.0.0.5", "www.example.test"),
		q(2, "10.0.0.5", "x7k2q9vz1m4p8d3w.test"),
		q(3, "10.0.0.5", strings.Repeat("a1b2c3d4e5", 5)+".tunnel.test"),
	}
	k := kinds(DNSAnomalies(ev))
	if k["dns-high-entropy"] != 1 || k["dns-long-name"] != 1 || len(k) != 2 {
		t.Errorf("got %v", k)
	}
}

func TestDNSManySubdomainsAndNXDomain(t *testing.T) {
	var ev []store.DNSEvent
	for i := 0; i < 60; i++ {
		ev = append(ev, q(int64(i), "10.0.0.5", fmt.Sprintf("n%d.data.test", i)))
		ev = append(ev, store.DNSEvent{TS: int64(i), Src: "8.8.8.8", Dst: "10.0.0.5", IsResponse: true, RCode: 3, QName: fmt.Sprintf("n%d.data.test", i)})
	}
	k := kinds(DNSAnomalies(ev))
	if k["dns-many-subdomains"] != 1 || k["dns-nxdomain-rate"] != 1 {
		t.Errorf("got %v", k)
	}
}

func TestNormalDNSIsQuiet(t *testing.T) {
	var ev []store.DNSEvent
	for i, n := range []string{"www.example.test", "mail.example.test", "api.service.test", "cdn.example.test"} {
		ev = append(ev, q(int64(i), "10.0.0.5", n))
	}
	if f := DNSAnomalies(ev); len(f) != 0 {
		t.Errorf("false positives: %+v", f)
	}
}

func tlsAt(ts int64, sni string) store.TLSEvent {
	return store.TLSEvent{TS: ts, Src: "10.0.0.5", Dst: "203.0.113.9", SPort: 50000, DPort: 443, SNI: sni}
}

func TestBeaconDetectedAndJitterTolerated(t *testing.T) {
	var ev []store.TLSEvent
	for i := 0; i < 10; i++ {
		ev = append(ev, tlsAt(int64(i*60+i%3), "c2.example.test")) // 60 s with +-1 s of jitter
	}
	f := Beacons(ev)
	if len(f) != 1 || f[0].Kind != "beacon" || !strings.Contains(f[0].Detail, "every 60 s") {
		t.Errorf("got %+v", f)
	}
}

func TestIrregularOrFewConnectionsAreNotBeacons(t *testing.T) {
	var irregular []store.TLSEvent
	for _, ts := range []int64{0, 5, 80, 83, 400, 410, 1000, 1002} {
		irregular = append(irregular, tlsAt(ts, "x.test"))
	}
	if len(Beacons(irregular)) != 0 {
		t.Error("irregular intervals flagged")
	}
	few := []store.TLSEvent{tlsAt(0, "x.test"), tlsAt(60, "x.test"), tlsAt(120, "x.test")}
	if len(Beacons(few)) != 0 {
		t.Error("three connections flagged")
	}
	var fast []store.TLSEvent
	for i := 0; i < 20; i++ {
		fast = append(fast, tlsAt(int64(i), "x.test")) // every second: ordinary polling
	}
	if len(Beacons(fast)) != 0 {
		t.Error("1 s polling flagged")
	}
}

func resp(name, ip string) store.DNSEvent {
	return store.DNSEvent{TS: 1, Src: "8.8.8.8", Dst: "10.0.0.5", IsResponse: true, QName: name, Answers: []store.Answer{{Type: 1, Data: ip}}}
}

func TestSNIMatchedMismatchedAndUnresolved(t *testing.T) {
	dns := []store.DNSEvent{resp("good.test", "203.0.113.9"), resp("front.test", "198.51.100.1")}
	tls := []store.TLSEvent{
		tlsAt(10, "good.test"),  // matches
		tlsAt(11, "front.test"), // resolved elsewhere than contacted
		{TS: 12, Src: "10.0.0.5", Dst: "192.0.2.77", DPort: 443, SNI: "never.test"},
		{TS: 13, Src: "10.0.0.5", Dst: "192.0.2.88", DPort: 443},
	}
	k := kinds(SNIMismatch(dns, tls))
	if k["sni-ip-mismatch"] != 1 || k["sni-ip-never-resolved"] != 1 || k["tls-no-sni-unresolved"] != 1 || len(k) != 3 {
		t.Errorf("got %v", k)
	}
	if SNIMismatch(nil, tls) != nil {
		t.Error("no DNS in the capture means nothing to compare")
	}
}

func TestFanOutAndPortSpread(t *testing.T) {
	var flows []store.Flow
	for i := 0; i < 120; i++ {
		flows = append(flows, store.Flow{Proto: 6, Src: "10.0.0.7", Dst: fmt.Sprintf("10.1.%d.%d", i/250, i%250), DPort: 22, Packets: 1})
	}
	for p := 1; p <= 30; p++ {
		flows = append(flows, store.Flow{Proto: 6, Src: "10.0.0.8", Dst: "10.9.9.9", DPort: p, Packets: 1})
	}
	flows = append(flows, store.Flow{Proto: 6, Src: "10.0.0.5", Dst: "203.0.113.9", DPort: 443, Packets: 50})
	k := kinds(FanOut(flows))
	if k["fan-out"] != 1 || k["port-spread"] != 1 || len(k) != 2 {
		t.Errorf("got %v", k)
	}
}

func TestAttributionAndUnattributed(t *testing.T) {
	hosts := []store.HostConn{{TS: 100, Host: "h1", PID: 4242, Process: "curl", Proto: 6, LAddr: "10.0.0.5", LPort: 50000, RAddr: "203.0.113.9", RPort: 443}}
	tls := []store.TLSEvent{
		{TS: 105, Src: "10.0.0.5", Dst: "203.0.113.9", DPort: 443, SNI: "known.test"},
		{TS: 106, Src: "10.0.0.5", Dst: "198.51.100.66", DPort: 443, SNI: "hidden.test"},
		{TS: 107, Src: "10.0.0.99", Dst: "198.51.100.66", DPort: 443, SNI: "other-host.test"}, // host without an agent: not judged
	}
	un := Unattributed(tls, hosts)
	if len(un) != 1 || un[0].Subject != "198.51.100.66" {
		t.Errorf("unattributed: %+v", un)
	}
	f := []Finding{{Kind: "beacon", Subject: "203.0.113.9", Src: "10.0.0.5", TS: 103}}
	Attribute(f, hosts)
	if f[0].Process != "curl" || f[0].PID != 4242 {
		t.Errorf("attribution: %+v", f[0])
	}
	if Unattributed(tls, nil) != nil {
		t.Error("without agent data nothing can be unattributed")
	}
}

func TestAttributionSkipsConnectionsWithoutProcess(t *testing.T) {
	hosts := []store.HostConn{{TS: 100, Host: "h1", PID: 0, Process: "-", Proto: 6, LAddr: "10.0.0.5", LPort: 22, RAddr: "203.0.113.9", RPort: 443}}
	f := []Finding{{Kind: "beacon", Subject: "203.0.113.9", Src: "10.0.0.5", TS: 100}}
	Attribute(f, hosts)
	if f[0].Process != "" || f[0].PID != 0 {
		t.Errorf("a placeholder process must not be attached: %+v", f[0])
	}
}

func TestAnalyzeOrdersBySeverity(t *testing.T) {
	r := Analyze(Input{DNS: []store.DNSEvent{q(1, "10.0.0.5", "x7k2q9vz1m4p8d3w.test")},
		TLS: []store.TLSEvent{{TS: 2, Src: "10.0.0.5", Dst: "192.0.2.77", DPort: 443, SNI: "never.test"}}})
	if len(r.Findings) < 2 || r.Findings[0].Severity != Medium || r.Findings[len(r.Findings)-1].Severity != Low {
		t.Errorf("order: %+v", r.Findings)
	}
	if r.Summary.DNSEvents != 1 || r.Summary.TLSEvents != 1 || r.Summary.FirstTS != 1 || r.Summary.LastTS != 2 {
		t.Errorf("summary: %+v", r.Summary)
	}
}
