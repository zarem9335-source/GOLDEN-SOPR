// GOLDEN SOPR — Kharej side (client) of the reverse tunnel.
//
// Kharej dials Iran, authenticates with the token on smux stream 0, and
// keeps a pool of parallel transport connections (size by preset). Each
// smux stream Iran opens carries an `open` message naming the backend to
// dial locally. If the primary transport fails, the configured fallback
// chain is tried in order; dead sessions are re-dialled with exponential
// backoff and jitter, and a 10s health ping keeps the pool honest.
package core

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/soprpack/soprpack/internal/transport"
	"github.com/xtaci/smux"
)

// poolSizeByPreset mirrors mux.PoolSize (core cannot import mux —
// mux imports core — so the policy lives here too).
func poolSizeByPreset(preset string) int {
	switch preset {
	case "eco":
		return 2
	case "turbo":
		return 8
	case "gaming":
		return 4
	default:
		return 4
	}
}

// backoffDelay returns 1s, 2s, 5s, 10s, 10s, ... with up to 25% jitter.
func backoffDelay(attempt int) time.Duration {
	base := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	d := base[len(base)-1]
	if attempt < len(base) {
		d = base[attempt]
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 4))
	return d + jitter
}

type clientSession struct {
	sess *smux.Session
	conn net.Conn
	ctrl net.Conn
}

// RunClient runs the Kharej side until ctx is done or Stop() is called.
func (e *Engine) RunClient(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	target := poolSizeByPreset(string(e.Tun.Preset))
	e.status(false, fmt.Sprintf("GOLDEN SOPR Kharej connecting to %s via %s (pool %d)",
		e.iranDialAddr(), e.Tun.Transport, target))

	var mu sync.Mutex
	sessions := map[*clientSession]bool{}

	remove := func(cs *clientSession) {
		mu.Lock()
		delete(sessions, cs)
		mu.Unlock()
		_ = cs.ctrl.Close()
		_ = cs.sess.Close()
		_ = cs.conn.Close()
	}

	// dialOne tries the primary transport, then the fallback chain.
	dialOne := func() (*clientSession, error) {
		names := append([]string{e.Tun.Transport}, e.Tun.Fallback...)
		var lastErr error
		for _, name := range names {
			factory, err := transport.Get(name)
			if err != nil {
				lastErr = err
				continue
			}
			dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			conn, err := factory.Dial(dctx, e.iranDialAddr(), e.Tun.Token, e.Tun.Extra)
			cancel()
			if err != nil {
				lastErr = err
				continue
			}
			sess, err := NewSmuxSession(conn, false)
			if err != nil {
				_ = conn.Close()
				lastErr = err
				continue
			}
			ctrl, err := sess.OpenStream()
			if err != nil {
				_ = sess.Close()
				_ = conn.Close()
				lastErr = err
				continue
			}
			_ = ctrl.SetDeadline(time.Now().Add(10 * time.Second))
			if err := WriteMsg(ctrl, ControlMsg{Type: "hello", Token: e.Tun.Token}); err != nil {
				_ = sess.Close()
				_ = conn.Close()
				lastErr = err
				continue
			}
			pong, err := ReadMsg(ctrl)
			_ = ctrl.SetDeadline(time.Time{})
			if err != nil || pong.Type != "pong" {
				_ = sess.Close()
				_ = conn.Close()
				if err == nil {
					err = fmt.Errorf("golden-sopr: bad hello reply")
				}
				lastErr = err
				continue
			}
			return &clientSession{sess: sess, conn: conn, ctrl: ctrl}, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("golden-sopr: no transport available")
		}
		return nil, lastErr
	}

	// serveSession accepts streams on one session until it dies.
	serveSession := func(cs *clientSession) {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer remove(cs)
			for {
				st, err := cs.sess.AcceptStream()
				if err != nil {
					return
				}
				e.wg.Add(1)
				go e.handleClientStream(st)
			}
		}()
		// Health ping every 10s on the control stream.
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer remove(cs)
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-e.quit:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					_ = cs.ctrl.SetDeadline(time.Now().Add(5 * time.Second))
					if err := WriteMsg(cs.ctrl, ControlMsg{Type: "ping"}); err != nil {
						return
					}
					msg, err := ReadMsg(cs.ctrl)
					_ = cs.ctrl.SetDeadline(time.Time{})
					if err != nil || msg.Type != "pong" {
						return
					}
				}
			}
		}()
	}

	// Pool manager: keep `target` live sessions, reconnecting with backoff.
	closeAll := func() {
		mu.Lock()
		for cs := range sessions {
			_ = cs.ctrl.Close()
			_ = cs.sess.Close()
			_ = cs.conn.Close()
		}
		mu.Unlock()
	}
	attempt := 0
	for {
		select {
		case <-e.quit:
			closeAll()
			return nil
		case <-ctx.Done():
			closeAll()
			return nil
		default:
		}
		mu.Lock()
		n := len(sessions)
		mu.Unlock()
		if n >= target {
			time.Sleep(time.Second)
			continue
		}
		cs, err := dialOne()
		if err != nil {
			e.status(false, "GOLDEN SOPR Kharej dial failed: "+err.Error())
			d := backoffDelay(attempt)
			attempt++
			select {
			case <-e.quit:
				return nil
			case <-ctx.Done():
				return nil
			case <-time.After(d):
			}
			continue
		}
		attempt = 0
		mu.Lock()
		sessions[cs] = true
		mu.Unlock()
		e.status(true, "GOLDEN SOPR Kharej connected ("+e.Tun.Transport+")")
		serveSession(cs)
	}
}

// iranDialAddr is host:port of the Iran server for the Kharej dial.
func (e *Engine) iranDialAddr() string {
	host := e.Tun.IranAddr
	if host == "" {
		return "127.0.0.1:" + strconv.Itoa(e.Tun.TunnelPort)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(e.Tun.TunnelPort))
}

// handleClientStream serves one forwarded flow opened by Iran.
func (e *Engine) handleClientStream(st net.Conn) {
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
	Pipe(st, backend, e.Metrics, e.Tun.Name)
}
