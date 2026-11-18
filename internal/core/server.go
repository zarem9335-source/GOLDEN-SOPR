// GOLDEN SOPR — Iran side (server) of the reverse tunnel.
//
// Iran listens on the tunnel port, authenticates the Kharej side by its
// token on smux stream 0, then serves forwarded flows: each smux stream
// opened by Kharej carries an `open` control message naming the backend
// to dial. Iran also listens on the forwarded ports itself — user traffic
// arriving there is sent over the tunnel to Kharej, which dials the real
// service. Optional PROXY protocol v1 and forwarded-UDP are supported.
package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soprpack/soprpack/internal/transport"
	"github.com/xtaci/smux"
)

// writeDatagramFrame writes one length-prefixed datagram frame.
func writeDatagramFrame(w io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// readDatagramFrame reads one length-prefixed datagram frame.
func readDatagramFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > uint32(max) {
		return nil, fmt.Errorf("golden-sopr: datagram frame too large (%d)", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// portMap is one parsed Ports entry: listen port on Iran -> backend addr.
type portMap struct {
	listen  int
	backend string
}

// parsePortMappings expands Tunnel.Ports entries:
// "8080=127.0.0.1:8081", "8080" (backend 127.0.0.1:8080),
// "8080-8082" (range, backend same port on localhost),
// "8080-8082=127.0.0.1:9080-9082" (range with offset backend).
func parsePortMappings(ports []string) []portMap {
	var out []portMap
	for _, raw := range ports {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		listenPart, backendPart, hasEq := strings.Cut(raw, "=")
		if !hasEq {
			backendPart = ""
		}
		lo, hi, ok := parsePortRange(listenPart)
		if !ok {
			continue
		}
		for p := lo; p <= hi; p++ {
			backend := backendPart
			if backend == "" {
				backend = fmt.Sprintf("127.0.0.1:%d", p)
			} else if blo, _, ok := parsePortRange(backend); ok {
				// backend is a bare port or a range start
				_ = blo
				backend = fmt.Sprintf("127.0.0.1:%d", blo+(p-lo))
			} else if strings.Contains(backend, ":") {
				// host:port — for a range, shift the port by the offset.
				if h, portStr, err := net.SplitHostPort(backend); err == nil {
					if bp, err := strconv.Atoi(portStr); err == nil {
						backend = net.JoinHostPort(h, strconv.Itoa(bp+(p-lo)))
					}
				}
			}
			out = append(out, portMap{listen: p, backend: backend})
		}
	}
	return out
}

func parsePortRange(s string) (lo, hi int, ok bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-") {
		a, b, _ := strings.Cut(s, "-")
		lo, err1 := strconv.Atoi(strings.TrimSpace(a))
		hi, err2 := strconv.Atoi(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || hi < lo {
			return 0, 0, false
		}
		return lo, hi, true
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, 0, false
	}
	return p, p, true
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// serverState holds the live smux sessions from Kharej.
type serverState struct {
	mu       sync.Mutex
	sessions []*smux.Session
	rr       int
}

func (s *serverState) add(sess *smux.Session) {
	s.mu.Lock()
	s.sessions = append(s.sessions, sess)
	s.mu.Unlock()
}

func (s *serverState) remove(sess *smux.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.sessions {
		if x == sess {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			return
		}
	}
}

// pick returns a live session (round-robin) or nil.
func (s *serverState) pick() *smux.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) == 0 {
		return nil
	}
	s.rr = (s.rr + 1) % len(s.sessions)
	return s.sessions[s.rr]
}

func (s *serverState) waitForSession(timeout time.Duration) *smux.Session {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sess := s.pick(); sess != nil && !sess.IsClosed() {
			return sess
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// RunServer runs the Iran side until ctx is done or Stop() is called.
func (e *Engine) RunServer(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	factory, err := transport.Get(e.Tun.Transport)
	if err != nil {
		return err
	}
	bindHost := hostOnly(e.Tun.IranAddr)
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	listenAddr := net.JoinHostPort(bindHost, strconv.Itoa(e.Tun.TunnelPort))
	ln, err := factory.Listen(ctx, listenAddr, e.Tun.Token, e.Tun.Extra)
	if err != nil {
		return fmt.Errorf("golden-sopr: iran listen %s (%s): %w", listenAddr, e.Tun.Transport, err)
	}
	defer ln.Close()
	e.status(true, "GOLDEN SOPR Iran listening on "+listenAddr+" via "+e.Tun.Transport)

	state := &serverState{}
	mappings := parsePortMappings(e.Tun.Ports)

	// Forwarded-port listeners (TCP, and UDP when AcceptUDP).
	for _, m := range mappings {
		m := m
		e.wg.Add(1)
		go e.serveForwardedTCP(ctx, state, m)
		if e.Tun.AcceptUDP {
			e.wg.Add(1)
			go e.serveForwardedUDP(ctx, state, m)
		}
	}

	// Tunnel accept loop.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-e.quit:
				case <-ctx.Done():
				default:
					e.status(false, "golden-sopr: tunnel accept: "+err.Error())
				}
				return
			}
			e.wg.Add(1)
			go e.handleServerConn(ctx, state, conn)
		}
	}()

	select {
	case <-e.quit:
	case <-ctx.Done():
	}
	_ = ln.Close()
	return nil
}

// handleServerConn authenticates one Kharej transport connection and
// serves its smux streams.
func (e *Engine) handleServerConn(ctx context.Context, state *serverState, conn net.Conn) {
	defer e.wg.Done()
	defer conn.Close()
	sess, err := NewSmuxSession(conn, true)
	if err != nil {
		return
	}
	defer sess.Close()

	// Stream 0 is the control stream: hello + token.
	ctrl, err := sess.AcceptStream()
	if err != nil {
		return
	}
	_ = ctrl.SetDeadline(time.Now().Add(15 * time.Second))
	hello, err := ReadMsg(ctrl)
	if err != nil || hello.Type != "hello" || hello.Token != e.Tun.Token {
		_ = ctrl.Close()
		return
	}
	_ = ctrl.SetDeadline(time.Time{})
	if err := WriteMsg(ctrl, ControlMsg{Type: "pong"}); err != nil {
		return
	}
	state.add(sess)
	defer state.remove(sess)
	e.status(true, "GOLDEN SOPR Kharej connected ("+e.Tun.Transport+")")

	// Control-stream ping/pong loop.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer ctrl.Close()
		for {
			msg, err := ReadMsg(ctrl)
			if err != nil {
				return
			}
			if msg.Type == "ping" {
				if err := WriteMsg(ctrl, ControlMsg{Type: "pong"}); err != nil {
					return
				}
			}
		}
	}()

	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		e.wg.Add(1)
		go e.handleServerStream(ctx, st)
	}
}

// handleServerStream serves one forwarded flow opened by Kharej.
func (e *Engine) handleServerStream(ctx context.Context, st net.Conn) {
	defer e.wg.Done()
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(15 * time.Second))
	open, err := ReadMsg(st)
	if err != nil || open.Type != "open" {
		return
	}
	_ = st.SetDeadline(time.Time{})
	if open.Proto == "udp" {
		e.serveUDPStream(st, open.Target)
		return
	}
	backend, err := net.DialTimeout("tcp", open.Target, 10*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()
	e.Metrics.AddConn(e.Tun.Name)
	defer e.Metrics.CloseConn(e.Tun.Name)
	// PROXY protocol v1: tell the backend the real client address.
	if e.Tun.Extra != nil && (e.Tun.Extra["proxy_protocol"] == "true" || e.Tun.Extra["proxy_protocol"] == "1") {
		if open.RemoteIP != "" {
			localPort := 0
			if la, ok := backend.LocalAddr().(*net.TCPAddr); ok {
				localPort = la.Port
			}
			iranIP := hostOnly(e.Tun.IranAddr)
			if iranIP == "" {
				iranIP = "127.0.0.1"
			}
			fmt.Fprintf(backend, "PROXY TCP4 %s %s %d %d\r\n",
				open.RemoteIP, iranIP, open.RemotePort, localPort)
		}
	}
	Pipe(st, backend, e.Metrics, e.Tun.Name)
}

// serveForwardedTCP listens on one forwarded port on Iran and pushes each
// user connection over the tunnel to Kharej.
func (e *Engine) serveForwardedTCP(ctx context.Context, state *serverState, m portMap) {
	defer e.wg.Done()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", m.listen))
	if err != nil {
		e.status(false, fmt.Sprintf("golden-sopr: forwarded port %d: %v", m.listen, err))
		return
	}
	defer ln.Close()
	for {
		select {
		case <-e.quit:
			return
		case <-ctx.Done():
			return
		default:
		}
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		user, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		e.wg.Add(1)
		go func(user net.Conn) {
			defer e.wg.Done()
			defer user.Close()
			sess := state.waitForSession(5 * time.Second)
			if sess == nil {
				return
			}
			st, err := sess.OpenStream()
			if err != nil {
				return
			}
			defer st.Close()
			remoteIP, remotePort := "", 0
			if ra, ok := user.RemoteAddr().(*net.TCPAddr); ok {
				remoteIP = ra.IP.String()
				remotePort = ra.Port
			}
			_ = st.SetDeadline(time.Now().Add(10 * time.Second))
			if err := WriteMsg(st, ControlMsg{Type: "open", Target: m.backend,
				RemoteIP: remoteIP, RemotePort: remotePort, Proto: "tcp"}); err != nil {
				return
			}
			_ = st.SetDeadline(time.Time{})
			e.Metrics.AddConn(e.Tun.Name)
			defer e.Metrics.CloseConn(e.Tun.Name)
			Pipe(st, user, e.Metrics, e.Tun.Name)
		}(user)
	}
}

// ---------------------------------------------------------------------------
// Forwarded UDP
// ---------------------------------------------------------------------------

// udpPeer is one UDP peer talking to a forwarded port on Iran.
type udpPeer struct {
	stream net.Conn
	mu     sync.Mutex
	last   time.Time
}

// serveForwardedUDP forwards UDP datagrams arriving on an Iran port over
// the tunnel to Kharej, which dials the UDP backend.
func (e *Engine) serveForwardedUDP(ctx context.Context, state *serverState, m portMap) {
	defer e.wg.Done()
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", m.listen))
	if err != nil {
		e.status(false, fmt.Sprintf("golden-sopr: forwarded udp %d: %v", m.listen, err))
		return
	}
	defer pc.Close()
	peers := map[string]*udpPeer{}
	var mu sync.Mutex
	// Reaper for idle peers.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-e.quit:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				for k, p := range peers {
					if time.Since(p.last) > 60*time.Second {
						_ = p.stream.Close()
						delete(peers, k)
					}
				}
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		_ = pc.SetDeadline(time.Now().Add(time.Second))
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-e.quit:
					return
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			return
		}
		key := peer.String()
		mu.Lock()
		p, ok := peers[key]
		if !ok {
			sess := state.waitForSession(5 * time.Second)
			if sess == nil {
				mu.Unlock()
				continue
			}
			st, err := sess.OpenStream()
			if err != nil {
				mu.Unlock()
				continue
			}
			_ = st.SetDeadline(time.Now().Add(10 * time.Second))
			if err := WriteMsg(st, ControlMsg{Type: "open", Target: m.backend, Proto: "udp"}); err != nil {
				_ = st.Close()
				mu.Unlock()
				continue
			}
			_ = st.SetDeadline(time.Time{})
			p = &udpPeer{stream: st, last: time.Now()}
			peers[key] = p
			// Reply loop: framed datagrams from Kharej -> back to this peer.
			e.wg.Add(1)
			go func(p *udpPeer, peer net.Addr) {
				defer e.wg.Done()
				defer p.stream.Close()
				for {
					dg, err := readDatagramFrame(p.stream, 65535)
					if err != nil {
						return
					}
					if _, err := pc.WriteTo(dg, peer); err != nil {
						return
					}
				}
			}(p, peer)
		}
		p.last = time.Now()
		mu.Unlock()
		p.mu.Lock()
		err = writeDatagramFrame(p.stream, buf[:n])
		p.mu.Unlock()
		if err != nil {
			mu.Lock()
			delete(peers, key)
			mu.Unlock()
			_ = p.stream.Close()
		}
	}
}

// bridgeUDPStream bridges one framed-datagram smux stream to a UDP backend.
// Used on both sides: whoever receives an `open` with Proto "udp" dials
// the named UDP backend and shuttles datagrams (length-prefixed frames).
func bridgeUDPStream(st net.Conn, target string) {
	backend, err := net.DialTimeout("udp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	// stream -> backend
	go func() {
		defer wg.Done()
		defer backend.Close()
		for {
			dg, err := readDatagramFrame(st, 65535)
			if err != nil {
				return
			}
			if _, err := backend.Write(dg); err != nil {
				return
			}
		}
	}()
	// backend -> stream
	go func() {
		defer wg.Done()
		defer st.Close()
		buf := make([]byte, 65535)
		for {
			_ = backend.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := backend.Read(buf)
			if err != nil {
				return
			}
			if err := writeDatagramFrame(st, buf[:n]); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

// serveUDPStream handles an `open` with Proto "udp" received on this side.
func (e *Engine) serveUDPStream(st net.Conn, target string) {
	bridgeUDPStream(st, target)
}
