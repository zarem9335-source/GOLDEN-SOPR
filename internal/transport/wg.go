// GOLDEN SOPR — "wg" transport (WireGuard-style L3 carrier).
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// "wg" is a WireGuard-style tunnel: a Noise-IK handshake (X25519 static
// keys, BLAKE2s chaining, ChaCha20-Poly1305 AEAD — see wgcommon.go) over
// UDP, carrying the reverse engine as a userspace virtual connection.
//
// Honest limits, read before deploying:
//   - The handshake is Noise-IK with the same primitives as WireGuard,
//     but it is NOT wire-compatible with kernel WireGuard / wg(8): the
//     prologue, message layout and key derivation are GOLDEN SOPR's own.
//     Both ends must run GOLDEN SOPR.
//   - A real TUN device (/dev/net/tun, root) is used only by the direct
//     L3 mode in internal/l3. The reverse engine uses the userspace
//     virtual connection below, which works without root and without TUN.
//     If you need kernel WireGuard interop, use wg-gaming's L3 mode
//     (internal/l3) or a real wg binary alongside GOLDEN SOPR.
package transport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

type wgFactory struct{ name string }

func (f *wgFactory) Info() Info {
	return Info{
		Name:        f.name,
		Family:      "wg",
		Encrypted:   true,
		NeedsRoot:   false,
		SupportsUDP: true,
		Desc:        "WireGuard-style Noise-IK over UDP (ChaCha20-Poly1305, BLAKE2s). Userspace virtual conn for the reverse engine; TUN for L3 lives in internal/l3. Not wire-compatible with kernel WireGuard — both ends must be GOLDEN SOPR.",
	}
}

func (f *wgFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wg: resolve %s: %w", addr, err)
	}
	pc, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("wg: dial udp: %w", err)
	}
	priv, pub, err := wgStaticKey(token, extra)
	if err != nil {
		pc.Close()
		return nil, err
	}
	peerPub, err := wgPeerPub(token, extra)
	if err != nil {
		pc.Close()
		return nil, err
	}
	_ = pub
	timeout := time.Duration(extraInt(extra, "handshake_timeout_ms", 5000)) * time.Millisecond
	dio := &directUDP{pc: pc}
	var hs *wgHandshake
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		hs, lastErr = wgHandshakeInitiator(dio, peerPub, priv, pub, timeout)
		if lastErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			pc.Close()
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if hs == nil {
		pc.Close()
		return nil, fmt.Errorf("wg: handshake failed: %w", lastErr)
	}
	// Best-effort DSCP: plain wg uses default (0); wg-gaming sets EF.
	if tos := extraInt(extra, "tos", 0); tos != 0 {
		_ = SetDSCP(pc, tos)
	}
	c := newWGConn(dio, hs, pc.LocalAddr(), pc.RemoteAddr())
	// Keepalive (WireGuard default 25s, configurable).
	ka := time.Duration(extraInt(extra, "keepalive_sec", 25)) * time.Second
	if ka > 0 {
		go func() {
			t := time.NewTicker(ka)
			defer t.Stop()
			for range t.C {
				if err := c.SendKeepalive(); err != nil {
					return
				}
			}
		}()
	}
	return c, nil
}

// wgListener accepts Noise handshakes on one shared UDP socket (udpHub)
// and hands each completed session to Accept as a net.Conn. The
// handshake reply goes out on the SAME socket that received the init —
// a connected UDP client drops replies from any other source port.
type wgListener struct {
	pc       *net.UDPConn
	hub      *udpHub
	priv     []byte
	pub      []byte
	acceptCh chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (f *wgFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wg: resolve %s: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("wg: listen udp: %w", err)
	}
	priv, pub, err := wgStaticKey(token, extra)
	if err != nil {
		pc.Close()
		return nil, err
	}
	l := &wgListener{pc: pc, priv: priv, pub: pub, acceptCh: make(chan net.Conn, 32), done: make(chan struct{})}
	l.hub = newUDPHub(pc, l.handleInit)
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return l, nil
}

func (l *wgListener) handleInit(msg []byte, src *net.UDPAddr) {
	hs, _, resp, err := wgHandshakeResponder(msg, l.priv, l.pub)
	if err != nil {
		return // unauthenticated peer: silent drop, like WireGuard
	}
	// Session owns a hubConn on the shared socket; the reply goes out
	// on that same socket so the connected client accepts it.
	c := newWGConn(l.hub.connFor(src), hs, l.pc.LocalAddr(), src)
	if _, err := l.hub.sendTo(resp, src); err != nil {
		c.Close()
		return
	}
	select {
	case l.acceptCh <- c:
	case <-l.done:
		c.Close()
	}
}

func (l *wgListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.done:
		return nil, fmt.Errorf("wg listener closed")
	}
}

func (l *wgListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		if l.hub != nil {
			l.hub.closeAll()
		}
		err = l.pc.Close()
	})
	return err
}

func (l *wgListener) Addr() net.Addr { return l.pc.LocalAddr() }

// wgKeyPair generates a fresh static keypair for a peer (base64).
// Operators store the private key in Extra["wg_private_key"] and give the
// public key to the other side as Extra["wg_public_key"].
func wgKeyPair() (privB64, pubB64 string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}
