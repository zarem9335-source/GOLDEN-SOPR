// Package metrics: per-tunnel traffic accounting for GOLDEN SOPR.
// Thread-safe counters; Snapshot is what the web panel and CLI read.
package metrics

import (
	"encoding/json"
	"sync"
	"time"
)

// TunnelStats is the accounting for one tunnel.
type TunnelStats struct {
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	Bytes     int64 `json:"bytes_total"`
	Conns     int64 `json:"conns"`
	ConnsOpen int64 `json:"conns_open"`
}

// Store holds counters for all tunnels plus global uptime.
type Store struct {
	mu      sync.Mutex
	started time.Time
	byTun   map[string]*TunnelStats
	conns   int64
}

// New creates a Store stamped with the process start time.
func New() *Store {
	return &Store{started: time.Now(), byTun: map[string]*TunnelStats{}}
}

func (s *Store) tun(name string) *TunnelStats {
	st, ok := s.byTun[name]
	if !ok {
		st = &TunnelStats{}
		s.byTun[name] = st
	}
	return st
}

// AddBytes counts n bytes of (undirected) traffic on a tunnel.
func (s *Store) AddBytes(tun string, n int64) {
	if s == nil || n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tun(tun)
	st.Bytes += n
	st.BytesUp += n // Pipe() cannot tell direction; counted as up, total is authoritative.
}

// AddUp counts n bytes sent toward the peer.
func (s *Store) AddUp(tun string, n int64) {
	if s == nil || n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tun(tun)
	st.Bytes += n
	st.BytesUp += n
}

// AddDown counts n bytes received from the peer.
func (s *Store) AddDown(tun string, n int64) {
	if s == nil || n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tun(tun)
	st.Bytes += n
	st.BytesDown += n
}

// AddConn records a new forwarded connection on a tunnel.
func (s *Store) AddConn(tun string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tun(tun)
	st.Conns++
	st.ConnsOpen++
	s.conns++
}

// CloseConn records a forwarded connection closing.
func (s *Store) CloseConn(tun string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.byTun[tun]; ok && st.ConnsOpen > 0 {
		st.ConnsOpen--
	}
	if s.conns > 0 {
		s.conns--
	}
}

// Reset clears all counters (keeps the start time).
func (s *Store) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byTun = map[string]*TunnelStats{}
	s.conns = 0
}

// Uptime returns how long this Store has existed.
func (s *Store) Uptime() time.Duration {
	if s == nil {
		return 0
	}
	return time.Since(s.started)
}

// Snapshot returns a JSON-friendly view of all counters.
func (s *Store) Snapshot() map[string]any {
	if s == nil {
		return map[string]any{"uptime_seconds": 0, "tunnels": map[string]any{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tuns := make(map[string]TunnelStats, len(s.byTun))
	for k, v := range s.byTun {
		tuns[k] = *v
	}
	return map[string]any{
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
		"started_at":     s.started.Format(time.RFC3339),
		"conns_open":     s.conns,
		"tunnels":        tuns,
	}
}

// MarshalJSON renders Snapshot as JSON.
func (s *Store) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Snapshot())
}
