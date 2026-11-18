// Package core: reverse tunnel engine shared by all transports.
// Iran = server (listens, forwards to local backends), Kharej = client
// (dials Iran, keeps a smux pool, dials the real service on demand).
// Control protocol: smux stream 0 is control (JSON), other streams are
// forwarded TCP flows; UDP flows are framed datagrams over a smux stream.
package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/soprpack/soprpack/internal/config"
	"github.com/soprpack/soprpack/internal/metrics"
	"github.com/xtaci/smux"
)

type ControlMsg struct {
	Type       string `json:"type"` // hello, open, udp, ping, pong
	Token      string `json:"token,omitempty"`
	StreamID   uint32 `json:"stream_id,omitempty"`
	Target     string `json:"target,omitempty"` // backend addr for this flow
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Proto      string `json:"proto,omitempty"` // tcp/udp
}

type Engine struct {
	Tun      config.Tunnel
	Metrics  *metrics.Store
	quit     chan struct{}
	wg       sync.WaitGroup
	OnStatus func(up bool, msg string)
}

func New(t config.Tunnel) *Engine {
	return &Engine{Tun: t, Metrics: metrics.New(), quit: make(chan struct{})}
}
func (e *Engine) Stop() {
	select {
	case <-e.quit:
	default:
		close(e.quit)
	}
	e.wg.Wait()
}
func (e *Engine) status(up bool, msg string) {
	if e.OnStatus != nil {
		e.OnStatus(up, msg)
	}
}

// Pipe copies both ways, counts bytes, honours MSS clamp via buf size.
func Pipe(a, b net.Conn, m *metrics.Store, tun string) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		defer dst.Close()
		buf := make([]byte, 32*1024)
		n, _ := io.CopyBuffer(dst, src, buf)
		if m != nil {
			m.AddBytes(tun, n)
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func WriteMsg(w io.Writer, msg ControlMsg) error {
	b, _ := json.Marshal(msg)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}
func ReadMsg(r io.Reader) (ControlMsg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return ControlMsg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 1<<20 {
		return ControlMsg{}, fmt.Errorf("control msg too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return ControlMsg{}, err
	}
	var m ControlMsg
	err := json.Unmarshal(b, &m)
	return m, err
}

func NewSmuxSession(c net.Conn, isServer bool) (*smux.Session, error) {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxReceiveBuffer = 4 * 1024 * 1024
	cfg.KeepAliveTimeout = 30 * time.Second
	if isServer {
		return smux.Server(c, cfg)
	}
	return smux.Client(c, cfg)
}

var _ = context.Background
