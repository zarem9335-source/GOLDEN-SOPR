// Package linktest: measures a route (latency / jitter / loss) and
// recommends a transport. Stdlib only. Based on BackPack by Amin Mohammadi
// (AminMGMT) https://github.com/AminMGMT/BackPack - AGPL-3.0.
package linktest

import (
	"fmt"
	"math"
	"net"
	"sort"
	"time"
)

// Result is one link-test run.
type Result struct {
	Addr       string             `json:"addr"`
	LatencyMs  float64            `json:"latency_ms"`
	JitterMs   float64            `json:"jitter_ms"`
	LossPct    float64            `json:"loss_pct"`
	Recommend  string             `json:"recommend"`
	Reason     string             `json:"reason"`
	Scores     map[string]float64 `json:"scores"`
	Probes     int                `json:"probes"`
	Throughput string             `json:"throughput,omitempty"`
}

// Measure dials addr with TCP 10 times (or fewer if seconds is small) and
// computes latency / jitter / loss. It never claims a tunnel works: it only
// measures the underlying TCP route, exactly like BackPack's Link Test.
func Measure(addr string, seconds int) (*Result, error) {
	if seconds <= 0 {
		seconds = 5
	}
	probes := 10
	if seconds < 3 {
		probes = 5
	}
	var lat []float64
	lost := 0
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for i := 0; i < probes; i++ {
		if time.Now().After(deadline) {
			break
		}
		start := time.Now()
		d := net.Dialer{Timeout: 2 * time.Second}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			lost++
			continue
		}
		_ = c.Close()
		lat = append(lat, float64(time.Since(start).Microseconds())/1000)
		time.Sleep(100 * time.Millisecond)
	}
	done := probes
	if done == 0 {
		return nil, fmt.Errorf("no probes completed")
	}
	// If we stopped early on the deadline, count only attempted probes.
	attempted := len(lat) + lost
	if attempted == 0 {
		return nil, fmt.Errorf("could not reach %s", addr)
	}
	loss := float64(lost) / float64(attempted) * 100
	latMs, jitMs := 0.0, 0.0
	if len(lat) > 0 {
		sort.Float64s(lat)
		// Median latency is robust against one slow probe.
		latMs = lat[len(lat)/2]
		var mean float64
		for _, v := range lat {
			mean += v
		}
		mean /= float64(len(lat))
		var variance float64
		for _, v := range lat {
			variance += (v - mean) * (v - mean)
		}
		jitMs = math.Sqrt(variance / float64(len(lat)))
	} else {
		latMs = 999
	}
	r := &Result{
		Addr:      addr,
		LatencyMs: round(latMs),
		JitterMs:  round(jitMs),
		LossPct:   round(loss),
		Probes:    attempted,
		Scores:    Score(latMs, jitMs, loss),
	}
	r.Recommend, r.Reason = Recommend(latMs, jitMs, loss, false)
	return r, nil
}

// Score rates each transport family 0-100 for the measured route.
// Higher is better. Gaming-oriented transports win on loss/jitter.
func Score(latencyMs, jitterMs, lossPct float64) map[string]float64 {
	s := map[string]float64{}
	// Base score falls with latency.
	base := 100 - latencyMs*0.4 - jitterMs*0.8 - lossPct*6
	clamp := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return round(v)
	}
	s["tcp"] = clamp(base)
	s["tcp-mux"] = clamp(base + 5)
	s["udp-kcp"] = clamp(base + 25 - lossPct) // FEC/KCP shrugs off loss
	s["wg-gaming"] = clamp(base + 35 - lossPct*0.5 - jitterMs*0.3)
	s["udp-quic"] = clamp(base + 15)
	s["wss"] = clamp(base - 5)
	s["tls-camou"] = clamp(base - 10)
	s["bond"] = clamp(base + 20)
	return s
}

// Recommend picks a transport for the measured route.
// gaming=true forces the gaming-optimised WireGuard tunnel (wg-gaming):
// it is the best tunnel for gaming WireGuard — 5s keepalive, MTU 1280,
// DSCP EF priority, packet duplication + FEC on game ports, <100ms failover.
func Recommend(latencyMs, jitterMs, lossPct float64, gaming bool) (string, string) {
	if gaming {
		return "wg-gaming", "gaming requested: wg-gaming has the lowest jitter/loss handling for game traffic (keepalive 5s, MTU 1280, DSCP EF, UDP duplication + FEC)"
	}
	switch {
	case lossPct > 5 || jitterMs > 30:
		return "wg-gaming", fmt.Sprintf("loss %.1f%% / jitter %.1fms is high: wg-gaming (or udp-kcp) recovers lost packets with FEC + duplication", lossPct, jitterMs)
	case lossPct > 2 || jitterMs > 15:
		return "udp-kcp", fmt.Sprintf("moderate loss %.1f%% / jitter %.1fms: UDP + KCP + FEC", lossPct, jitterMs)
	case latencyMs < 50:
		return "tcp-mux", fmt.Sprintf("clean low-latency route (%.0fms): TCP Mux is fastest", latencyMs)
	case latencyMs > 200:
		return "udp-quic", fmt.Sprintf("high latency (%.0fms): QUIC handles long RTT better than plain TCP", latencyMs)
	default:
		return "tcp-mux", fmt.Sprintf("average route (%.0fms, loss %.1f%%): TCP Mux is a safe default", latencyMs, lossPct)
	}
}

// RecommendForFiltered is used when the TCP route is unreachable/filtered:
// camouflaged transports are the only honest recommendation.
func RecommendForFiltered() (string, string) {
	return "tls-camou", "route looks filtered/blocked: use tls-camou, wss or reality (camouflaged TLS) instead of plain TCP"
}

func round(v float64) float64 { return math.Round(v*100) / 100 }
