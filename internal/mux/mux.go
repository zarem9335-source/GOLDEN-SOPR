// Package mux: smux session helpers for GOLDEN SOPR.
// core.NewSmuxSession is the canonical constructor; this package re-exports
// it and adds the pool-size-by-preset policy shared by the Iran/Kharej engines.
package mux

import (
	"net"

	"github.com/soprpack/soprpack/internal/core"
	"github.com/xtaci/smux"
)

// Session is a smux multiplexed session over one transport connection.
type Session = smux.Session

// NewSession wraps conn in a smux session (server side on Iran, client on Kharej).
func NewSession(conn net.Conn, isServer bool) (*smux.Session, error) {
	return core.NewSmuxSession(conn, isServer)
}

// PoolSize returns how many parallel transport connections the Kharej side
// keeps open for a preset. Gaming keeps a small, low-latency pool; turbo
// maximises throughput; eco minimises connections.
func PoolSize(preset string) int {
	switch preset {
	case "eco":
		return 2
	case "turbo":
		return 8
	case "gaming":
		return 4
	default: // balanced and anything unknown
		return 4
	}
}

// PoolSizeForPreset is an alias kept for readability at call sites.
func PoolSizeForPreset(preset string) int { return PoolSize(preset) }
