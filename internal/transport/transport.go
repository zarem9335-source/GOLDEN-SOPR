// Package transport: transport registry. Every transport only has to
// provide a raw net.Conn (Dial for Kharej, Listen for Iran); core wraps
// it in smux, does auth, forwarding, UDP, PROXY protocol and metrics.
// That is how one engine carries all 12 BackPack transports + the new ones.
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
)

type Info struct {
	Name        string
	Family      string // tcp, udp, ws, icmp, dns, wg, grpc, bond
	Encrypted   bool
	NeedsRoot   bool
	SupportsUDP bool
	NeedsCert   bool
	Desc        string
}

type Factory interface {
	Info() Info
	Dial(ctx context.Context, addr string, token string, extra map[string]string) (net.Conn, error)
	Listen(ctx context.Context, addr string, token string, extra map[string]string) (net.Listener, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

func Register(f Factory) {
	mu.Lock()
	defer mu.Unlock()
	registry[f.Info().Name] = f
}

func Get(name string) (Factory, error) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown transport %q", name)
	}
	return f, nil
}

func List() []Info {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Info, 0, len(registry))
	for _, f := range registry {
		out = append(out, f.Info())
	}
	return out
}

func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	return out
}

// FramedConn: length-prefixed stream over a packet conn (UDP/DNS/ICMP).
// Used by udp/dns/xdi transports so core sees a net.Conn.
type FramedConn struct {
	net.Conn
}
