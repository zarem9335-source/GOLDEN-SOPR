// Package monitor: health ticker, auto-restart and failover for tunnels.
// Stdlib only; the engine is injected as callbacks so this package does not
// depend on core (which is built by another agent). Based on BackPack by
// Amin Mohammadi (AminMGMT) https://github.com/AminMGMT/BackPack - AGPL-3.0.
package monitor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/soprpack/soprpack/internal/config"
)

// CheckFunc probes a tunnel and returns nil when it is healthy.
type CheckFunc func(ctx context.Context, t config.Tunnel) error

// RestartFunc restarts a tunnel. It is called on failure (rate-limited).
type RestartFunc func(ctx context.Context, t config.Tunnel) error

// AlertFunc is called on down/up transitions (Telegram bot, log, ...).
type AlertFunc func(t config.Tunnel, up bool, msg string)

// Monitor watches tunnels on a ticker.
type Monitor struct {
	Interval    time.Duration
	MaxRestarts int         // per hour, per tunnel
	HistoryFile string      // alert history (JSON lines), "" = disabled
	Check       CheckFunc   // default: TCP dial to IranAddr:TunnelPort
	Restart     RestartFunc // nil = alert only, no restart
	Alert       AlertFunc   // nil = no alerts

	mu       sync.Mutex
	restarts map[string][]time.Time
	up       map[string]bool
	running  map[string]context.CancelFunc
}

func New(interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Monitor{
		Interval: interval, MaxRestarts: 5,
		restarts: map[string][]time.Time{}, up: map[string]bool{},
		running: map[string]context.CancelFunc{},
	}
}

// DefaultCheck dials the tunnel port; a refused/timeout dial means DOWN.
// It does not authenticate — authentication is the health command's job.
func DefaultCheck(ctx context.Context, t config.Tunnel) error {
	addr := net.JoinHostPort(hostOf(t), fmt.Sprint(t.TunnelPort))
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

func hostOf(t config.Tunnel) string {
	h, _, err := net.SplitHostPort(t.IranAddr)
	if err == nil {
		return h
	}
	return t.IranAddr
}

// IsUp reports the last known state of a tunnel (false if never checked).
func (m *Monitor) IsUp(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.up[name]
}

// Run watches tunnels until ctx ends. Failover: if the primary IranAddr
// fails and t.Extra["fallback_addrs"] (comma-separated) is set, the monitor
// reports the first reachable fallback addr via Alert so the caller can
// switch IranAddr to it.
func (m *Monitor) Run(ctx context.Context, tunnels []config.Tunnel) {
	check := m.Check
	if check == nil {
		check = DefaultCheck
	}
	tick := time.NewTicker(m.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, t := range tunnels {
				m.checkOne(ctx, t, check)
			}
		}
	}
}

func (m *Monitor) checkOne(ctx context.Context, t config.Tunnel, check CheckFunc) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := check(cctx, t)
	up := err == nil

	m.mu.Lock()
	prev, seen := m.up[t.Name]
	m.up[t.Name] = up
	m.mu.Unlock()

	if !seen || prev == up {
		if !up {
			m.maybeRestart(ctx, t, err)
		}
		return
	}
	// Transition.
	msg := "tunnel up"
	if !up {
		msg = "tunnel down: " + err.Error()
		if fb := FirstReachableFallback(ctx, t); fb != "" {
			msg += " | failover candidate: " + fb
		}
	}
	m.appendHistory(t.Name, up, msg)
	if m.Alert != nil {
		m.Alert(t, up, msg)
	}
	if !up {
		m.maybeRestart(ctx, t, err)
	}
}

func (m *Monitor) maybeRestart(ctx context.Context, t config.Tunnel, err error) {
	if m.Restart == nil {
		return
	}
	m.mu.Lock()
	now := time.Now()
	cut := now.Add(-time.Hour)
	kept := m.restarts[t.Name][:0]
	for _, ts := range m.restarts[t.Name] {
		if ts.After(cut) {
			kept = append(kept, ts)
		}
	}
	m.restarts[t.Name] = kept
	if len(kept) >= m.MaxRestarts {
		m.mu.Unlock()
		m.appendHistory(t.Name, false, fmt.Sprintf("restart rate-limit reached (%d/hour), not restarting: %v", m.MaxRestarts, err))
		return
	}
	m.restarts[t.Name] = append(m.restarts[t.Name], now)
	m.mu.Unlock()
	_ = m.Restart(ctx, t)
	m.appendHistory(t.Name, false, "auto-restarted after failure: "+err.Error())
}

// FirstReachableFallback dials each Extra["fallback_addrs"] entry and
// returns the first reachable one, or "".
func FirstReachableFallback(ctx context.Context, t config.Tunnel) string {
	addrs := configFallbackAddrs(t)
	for _, a := range addrs {
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.DialContext(ctx, "tcp", a)
		if err == nil {
			_ = c.Close()
			return a
		}
	}
	return ""
}

func configFallbackAddrs(t config.Tunnel) []string {
	if t.Extra == nil {
		return nil
	}
	raw := t.Extra["fallback_addrs"]
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range splitComma(raw) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, trimSpace(cur))
			cur = ""
		} else {
			cur += string(r)
		}
	}
	out = append(out, trimSpace(cur))
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func (m *Monitor) appendHistory(name string, up bool, msg string) {
	if m.HistoryFile == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.HistoryFile), 0o700)
	f, err := os.OpenFile(m.HistoryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	state := "UP"
	if !up {
		state = "DOWN"
	}
	fmt.Fprintf(f, "%s %s %s %s\n", time.Now().Format(time.RFC3339), name, state, msg)
}
