// Package transport — GOLDEN SOPR shared WireGuard helpers.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// wgcommon.go: the crypto + socket primitives shared by the "wg" and
// "wg-gaming" transports: a Noise-IK-style handshake (X25519 static keys,
// BLAKE2s chaining, ChaCha20-Poly1305), AEAD packet framing over UDP,
// /dev/net/tun handling, DSCP marking, game-port classification,
// XOR FEC and duplicate suppression.
package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
)

// DSCP EF (Expedited Forwarding) — the marking wg-gaming puts on game
// traffic so routers / QoS queues treat it as latency-sensitive.
const DSCPEF = 184 // 0xb8, DSCP 46 (EF)

// GOLDEN SOPR gaming defaults.
const (
	GamingMTUDefault       = 1280
	GamingMSSDefault       = 1240 // MTU - 40 (IPv6 + UDP + WG overhead)
	GamingKeepaliveDefault = 5    // seconds
	GamingHandshakeRetryMs = 500
	GamingRTTSwitchMs      = 120
	GamingLossSwitchPct    = 3.0
)

var wgPrologue = []byte("GOLDEN SOPR Noise_IK_25519_ChaChaPoly_BLAKE2s")

func blakeSum(data ...[]byte) []byte {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// ---- static keys ---------------------------------------------------------

// wgStaticKey derives (or parses) the long-term X25519 keypair for a peer.
// Extra keys: wg_private_key (base64, 32 bytes). Otherwise the key is
// derived deterministically from the tunnel token so both sides agree
// without exchanging files; for production use set wg_private_key.
func wgStaticKey(token string, extra map[string]string) (priv, pub []byte, err error) {
	if s := strings.TrimSpace(extra["wg_private_key"]); s != "" {
		priv, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			priv, err = base64.RawURLEncoding.DecodeString(s)
		}
		if err != nil || len(priv) != 32 {
			return nil, nil, fmt.Errorf("wg_private_key must be base64 of 32 bytes")
		}
	} else {
		sum := sha256.Sum256([]byte("golden-sopr-wg-static:" + token))
		priv = sum[:]
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func wgPeerPub(token string, extra map[string]string) ([]byte, error) {
	if s := strings.TrimSpace(extra["wg_public_key"]); s != "" {
		pub, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			pub, err = base64.RawURLEncoding.DecodeString(s)
		}
		if err != nil || len(pub) != 32 {
			return nil, fmt.Errorf("wg_public_key must be base64 of 32 bytes")
		}
		return pub, nil
	}
	// Peer uses the same token-derived key when no explicit key is set.
	_, pub, err := wgStaticKey(token, extra)
	return pub, err
}

func wgPeerPriv(token string, extra map[string]string) ([]byte, error) {
	priv, _, err := wgStaticKey(token, extra)
	return priv, err
}

// ---- Noise-IK-style handshake --------------------------------------------
// Message 1 (initiator -> responder):
//   [0x01][eph_pub 32][enc_static 48][enc_timestamp 28]
// Message 2 (responder -> initiator):
//   [0x02][eph_pub 32][enc_empty 16]
// Then both sides derive directional session keys from the final
// chaining key. This is the Noise IK pattern (two DHs, static keys
// authenticated in both directions); it is not wire-compatible with
// kernel WireGuard, which uses its own Noise_IKpsk2 variant — see wg.go.

type wgHandshake struct {
	ck, h   []byte
	sendKey []byte
	recvKey []byte
}

func wgMixKey(ck, dh []byte) (newCK, k []byte) {
	newCK = blakeSum(ck, dh)
	k = blakeSum(newCK, []byte{0x01})
	return newCK, k
}

func wgAEADSeal(key, nonce, aad, plain []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plain, aad), nil
}

func wgAEADOpen(key, nonce, aad, ct []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ct, aad)
}

func wgZeroNonce() []byte { return make([]byte, chacha20poly1305.NonceSize) }

// wgHandshakeInitiator runs the initiator side over one UDP peer.
// pc must be packet-oriented: one Read returns one datagram.
func wgHandshakeInitiator(pc packetIO, peerPub, staticPriv, staticPub []byte, timeout time.Duration) (*wgHandshake, error) {
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	ck := blakeSum(wgPrologue)
	h := blakeSum(ck, wgPrologue)
	h = blakeSum(h, peerPub) // responder static is part of the prologue hash

	dh1, err := curve25519.X25519(ephPriv, peerPub)
	if err != nil {
		return nil, err
	}
	ck, k1 := wgMixKey(ck, dh1)
	h = blakeSum(h, ephPub)
	encStatic, err := wgAEADSeal(k1, wgZeroNonce(), h, staticPub)
	if err != nil {
		return nil, err
	}
	h = blakeSum(h, encStatic)

	dh2, err := curve25519.X25519(staticPriv, peerPub)
	if err != nil {
		return nil, err
	}
	ck, k2 := wgMixKey(ck, dh2)
	ts := make([]byte, 12)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().UnixNano()))
	encTS, err := wgAEADSeal(k2, wgZeroNonce(), h, ts)
	if err != nil {
		return nil, err
	}
	h = blakeSum(h, encTS)

	msg := make([]byte, 0, 1+32+48+28)
	msg = append(msg, 0x01)
	msg = append(msg, ephPub...)
	msg = append(msg, encStatic...)
	msg = append(msg, encTS...)

	if _, err := pc.Write(msg); err != nil {
		return nil, err
	}
	resp := make([]byte, 1024)
	if err := pc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	n, err := pc.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("wg handshake: no response: %w", err)
	}
	if n < 1+32+16 || resp[0] != 0x02 {
		return nil, errors.New("wg handshake: bad response")
	}
	respEph := resp[1:33]
	dh3, err := curve25519.X25519(ephPriv, respEph)
	if err != nil {
		return nil, err
	}
	ck, k3 := wgMixKey(ck, dh3)
	h = blakeSum(h, respEph)
	if _, err := wgAEADOpen(k3, wgZeroNonce(), h, resp[33:n]); err != nil {
		return nil, fmt.Errorf("wg handshake: responder auth failed: %w", err)
	}
	dh4, err := curve25519.X25519(staticPriv, respEph)
	if err != nil {
		return nil, err
	}
	ck, _ = wgMixKey(ck, dh4)
	sendKey := blakeSum(ck, []byte("initiator-send"))
	recvKey := blakeSum(ck, []byte("responder-send"))
	return &wgHandshake{ck: ck, h: h, sendKey: sendKey, recvKey: recvKey}, nil
}

// wgHandshakeResponder validates message 1 and builds message 2.
// Returns the handshake and the initiator's static public key.
func wgHandshakeResponder(msg []byte, staticPriv, staticPub []byte) (*wgHandshake, []byte, []byte, error) {
	if len(msg) < 1+32+48+28 || msg[0] != 0x01 {
		return nil, nil, nil, errors.New("wg handshake: bad init message")
	}
	initEph := msg[1:33]
	encStatic := msg[33:81]
	encTS := msg[81:109]

	ck := blakeSum(wgPrologue)
	h := blakeSum(ck, wgPrologue)
	h = blakeSum(h, staticPub)

	dh1, err := curve25519.X25519(staticPriv, initEph)
	if err != nil {
		return nil, nil, nil, err
	}
	ck, k1 := wgMixKey(ck, dh1)
	h = blakeSum(h, initEph)
	initStatic, err := wgAEADOpen(k1, wgZeroNonce(), h, encStatic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wg handshake: initiator auth failed: %w", err)
	}
	h = blakeSum(h, encStatic)

	dh2, err := curve25519.X25519(staticPriv, initStatic)
	if err != nil {
		return nil, nil, nil, err
	}
	ck, k2 := wgMixKey(ck, dh2)
	if _, err := wgAEADOpen(k2, wgZeroNonce(), h, encTS); err != nil {
		return nil, nil, nil, fmt.Errorf("wg handshake: bad timestamp: %w", err)
	}
	h = blakeSum(h, encTS)

	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, nil, nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, err
	}
	dh3, err := curve25519.X25519(ephPriv, initEph)
	if err != nil {
		return nil, nil, nil, err
	}
	ck, k3 := wgMixKey(ck, dh3)
	h = blakeSum(h, ephPub)
	encEmpty, err := wgAEADSeal(k3, wgZeroNonce(), h, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	dh4, err := curve25519.X25519(ephPriv, initStatic)
	if err != nil {
		return nil, nil, nil, err
	}
	ck, _ = wgMixKey(ck, dh4)
	resp := make([]byte, 0, 1+32+16)
	resp = append(resp, 0x02)
	resp = append(resp, ephPub...)
	resp = append(resp, encEmpty...)
	// Responder's send key is the initiator's recv key and vice versa.
	sendKey := blakeSum(ck, []byte("responder-send"))
	recvKey := blakeSum(ck, []byte("initiator-send"))
	return &wgHandshake{ck: ck, h: h, sendKey: sendKey, recvKey: recvKey}, initStatic, resp, nil
}

// ---- AEAD packet conn ----------------------------------------------------
// wgPacketConn is a net.Conn over one UDP session: every Write is one
// AEAD data packet [0x03][counter 8][ciphertext], every Read returns one
// decrypted datagram payload (streamed to the caller as a byte stream).

const (
	wgMsgData      = 0x03
	wgMsgKeepalive = 0x04
)

// packetIO is one UDP peer: one Read returns one datagram (connected
// socket on the client, demultiplexed shared socket on the server).
// This is why the server must answer handshakes from the SAME socket
// that received them: a connected UDP socket drops replies from any
// other source port, which is exactly how a naive "dial a new socket
// per session" implementation silently times out.
type packetIO interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetTOS(tos int) error
}

// directUDP is packetIO over a connected *net.UDPConn (client side).
type directUDP struct{ pc *net.UDPConn }

func (d *directUDP) Read(p []byte) (int, error)         { return d.pc.Read(p) }
func (d *directUDP) Write(p []byte) (int, error)        { return d.pc.Write(p) }
func (d *directUDP) Close() error                       { return d.pc.Close() }
func (d *directUDP) LocalAddr() net.Addr                { return d.pc.LocalAddr() }
func (d *directUDP) RemoteAddr() net.Addr               { return d.pc.RemoteAddr() }
func (d *directUDP) SetReadDeadline(t time.Time) error  { return d.pc.SetReadDeadline(t) }
func (d *directUDP) SetWriteDeadline(t time.Time) error { return d.pc.SetWriteDeadline(t) }
func (d *directUDP) SetTOS(tos int) error               { return SetDSCP(d.pc, tos) }

// udpHub demultiplexes one listening UDP socket across many peers
// (server side): handshake-init packets go to onInit, data packets are
// routed to the hubConn of their source address.
type udpHub struct {
	pc     *net.UDPConn
	mu     sync.Mutex
	peers  map[string]*hubConn
	onInit func(msg []byte, src *net.UDPAddr)
	done   chan struct{}
}

func newUDPHub(pc *net.UDPConn, onInit func([]byte, *net.UDPAddr)) *udpHub {
	h := &udpHub{pc: pc, peers: map[string]*hubConn{}, onInit: onInit, done: make(chan struct{})}
	go h.readLoop()
	return h
}

func (h *udpHub) connFor(src *net.UDPAddr) *hubConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.peers[src.String()]; ok {
		return c
	}
	c := newHubConn(h, src)
	h.peers[src.String()] = c
	return c
}

func (h *udpHub) sendTo(p []byte, dst *net.UDPAddr) (int, error) {
	return h.pc.WriteToUDP(p, dst)
}

func (h *udpHub) readLoop() {
	tmp := make([]byte, 65535)
	for {
		n, src, err := h.pc.ReadFromUDP(tmp)
		if err != nil {
			return
		}
		if n < 1 {
			continue
		}
		if tmp[0] == 0x01 { // handshake init: new (or re-)handshake
			if h.onInit != nil {
				msg := append([]byte(nil), tmp[:n]...)
				go h.onInit(msg, src)
			}
			continue
		}
		h.mu.Lock()
		c, ok := h.peers[src.String()]
		h.mu.Unlock()
		if !ok {
			continue // data from an unknown peer: drop
		}
		c.deliver(append([]byte(nil), tmp[:n]...))
	}
}

func (h *udpHub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.peers {
		c.Close()
	}
}

// hubConn is packetIO for one peer on a shared udpHub socket.
// Close only detaches this peer; the shared socket stays open.
type hubConn struct {
	hub      *udpHub
	peer     *net.UDPAddr
	mu       sync.Mutex
	cond     *sync.Cond
	queue    [][]byte
	leftover []byte
	closed   bool
	deadline time.Time
}

func newHubConn(h *udpHub, peer *net.UDPAddr) *hubConn {
	c := &hubConn{hub: h, peer: peer}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *hubConn) deliver(d []byte) {
	c.mu.Lock()
	if !c.closed {
		c.queue = append(c.queue, d)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
}

func (c *hubConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	for len(c.queue) == 0 {
		if c.closed {
			return 0, os.ErrClosed
		}
		if !c.deadline.IsZero() && time.Now().After(c.deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
	d := c.queue[0]
	c.queue = c.queue[1:]
	n := copy(p, d)
	if n < len(d) {
		c.leftover = append(c.leftover, d[n:]...)
	}
	return n, nil
}

func (c *hubConn) Write(p []byte) (int, error) { return c.hub.sendTo(p, c.peer) }
func (c *hubConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}
func (c *hubConn) LocalAddr() net.Addr  { return c.hub.pc.LocalAddr() }
func (c *hubConn) RemoteAddr() net.Addr { return c.peer }
func (c *hubConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}
func (c *hubConn) SetWriteDeadline(t time.Time) error {
	return c.hub.pc.SetWriteDeadline(t)
}
func (c *hubConn) SetTOS(tos int) error { return SetDSCP(c.hub.pc, tos) }

type wgPacketConn struct {
	io       packetIO
	hs       *wgHandshake
	local    net.Addr
	remote   net.Addr
	sendCtr  uint64
	recvCtr  uint64
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	closed   bool
	readErr  error
	deadline time.Time
}

func newWGConn(io packetIO, hs *wgHandshake, local, remote net.Addr) *wgPacketConn {
	c := &wgPacketConn{io: io, hs: hs, local: local, remote: remote}
	c.cond = sync.NewCond(&c.mu)
	go c.readLoop()
	return c
}

func (c *wgPacketConn) readLoop() {
	tmp := make([]byte, 65535)
	for {
		n, err := c.io.Read(tmp)
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			c.closed = true
			c.cond.Broadcast()
			c.mu.Unlock()
			return
		}
		if n < 1+8+16 {
			continue
		}
		if tmp[0] == wgMsgKeepalive {
			continue
		}
		if tmp[0] != wgMsgData {
			continue
		}
		ctr := binary.BigEndian.Uint64(tmp[1:9])
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint64(nonce[4:], ctr)
		plain, err := wgAEADOpen(c.hs.recvKey, nonce, nil, tmp[9:n])
		if err != nil {
			continue // bad packet: drop, never deliver garbage
		}
		c.mu.Lock()
		if ctr > c.recvCtr {
			c.recvCtr = ctr
		}
		c.buf = append(c.buf, plain...)
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

func (c *wgPacketConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.buf) == 0 {
		if c.closed {
			if c.readErr != nil {
				return 0, c.readErr
			}
			return 0, os.ErrClosed
		}
		if !c.deadline.IsZero() && time.Now().After(c.deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *wgPacketConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	ctr := c.sendCtr
	c.sendCtr++
	c.mu.Unlock()
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	ct, err := wgAEADSeal(c.hs.sendKey, nonce, nil, p)
	if err != nil {
		return 0, err
	}
	pkt := make([]byte, 0, 1+8+len(ct))
	pkt = append(pkt, wgMsgData)
	var cb [8]byte
	binary.BigEndian.PutUint64(cb[:], ctr)
	pkt = append(pkt, cb[:]...)
	pkt = append(pkt, ct...)
	if _, err := c.io.Write(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SendKeepalive sends an empty authenticated keepalive packet.
func (c *wgPacketConn) SendKeepalive() error {
	_, err := c.io.Write([]byte{wgMsgKeepalive})
	return err
}

func (c *wgPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return c.io.Close()
}
func (c *wgPacketConn) LocalAddr() net.Addr  { return c.local }
func (c *wgPacketConn) RemoteAddr() net.Addr { return c.remote }
func (c *wgPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}
func (c *wgPacketConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *wgPacketConn) SetWriteDeadline(t time.Time) error { return c.io.SetWriteDeadline(t) }

// SetTOS marks the underlying UDP socket (DSCP EF for gaming).
func (c *wgPacketConn) SetTOS(tos int) error { return c.io.SetTOS(tos) }

// ---- DSCP / socket priority ----------------------------------------------

// SetDSCP sets IP_TOS / IPV6_TCLASS (and SO_PRIORITY on Linux) on a UDP/TCP
// conn. tos is the full TOS byte, e.g. DSCPEF (184) for Expedited Forwarding.
func SetDSCP(conn net.Conn, tos int) error {
	raw, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return errors.New("conn does not expose SyscallConn")
	}
	sc, err := raw.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = sc.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos); e != nil {
			serr = e
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos)
		// SO_PRIORITY 6: highest user priority, helps local qdisc ordering.
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY, 6)
	})
	if err != nil {
		return err
	}
	return serr
}

// ---- /dev/net/tun --------------------------------------------------------

// OpenTUN opens /dev/net/tun as a TUN device (no packet-info header).
// Returns the file and the kernel-assigned interface name. Requires root
// and /dev/net/tun; callers must fall back to the userspace virtual conn
// when this fails — the reverse engine works without TUN.
func OpenTUN(name string) (*os.File, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w (need root + tun module; falling back to userspace conn)", err)
	}
	const (
		iffTun  = 0x0001
		iffNoPi = 0x1000
	)
	var ifr [40]byte
	if name != "" {
		copy(ifr[:16], name)
	}
	binary.LittleEndian.PutUint16(ifr[16:18], iffTun|iffNoPi)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		f.Close()
		return nil, "", fmt.Errorf("TUNSETIFF: %v", errno)
	}
	ifName := strings.TrimRight(string(ifr[:16]), "\x00")
	return f, ifName, nil
}

// ---- game ports ----------------------------------------------------------

// GamePortSet is the set of destination ports that get gaming priority
// (DSCP EF, duplication, jitter-buffer bypass of FEC queue).
type GamePortSet struct {
	mu    sync.RWMutex
	ports map[int]bool
}

// NewGamePortSet builds a set from an explicit list, or the defaults when
// the list is empty.
func NewGamePortSet(ports []int) *GamePortSet {
	s := &GamePortSet{ports: map[int]bool{}}
	if len(ports) == 0 {
		ports = GamePortsDefaultList()
	}
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			s.ports[p] = true
		}
	}
	return s
}

// ParseGamePorts parses "27015,3074,3478" (also "27015-27020" ranges).
func ParseGamePorts(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			kv := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(kv[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(kv[1]))
			if e1 == nil && e2 == nil {
				for p := lo; p <= hi && p <= 65535; p++ {
					out = append(out, p)
				}
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// IsGamePort reports whether a destination port is a known game port.
func (s *GamePortSet) IsGamePort(port int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ports[port]
}

// Classify returns "game" or "bulk" for a destination port.
func (s *GamePortSet) Classify(port int) string {
	if s.IsGamePort(port) {
		return "game"
	}
	return "bulk"
}

// GamePortsDefaultList returns the built-in well-known game ports.
// Kept here (not importing config) so transport stays dependency-light.
func GamePortsDefaultList() []int {
	return []int{27015, 27016, 27017, 27018, 27019, 27020, 3074, 3075, 3478, 3479, 3480, 5222, 5795, 7000, 7100, 7200, 7300, 7400, 7500, 5060, 5062, 12000, 13000, 14000, 15000, 16000, 17000, 18000, 19000, 20000, 30000, 40000, 50000, 7777, 7778, 27005, 27006, 4380, 27036, 27037, 3478, 3659, 6000, 9000, 10000, 25565}
}

// ---- gaming stats / path monitor -----------------------------------------

// GamingStats is the live latency picture for a gaming tunnel.
type GamingStats struct {
	mu       sync.RWMutex
	RTTms    float64
	JitterMs float64
	LossPct  float64
	Sent     uint64
	Recv     uint64
	Lost     uint64
	BestPath string
	Switches uint64
	lastRTT  float64
}

func (s *GamingStats) RecordRTT(rttMs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastRTT > 0 {
		d := rttMs - s.lastRTT
		if d < 0 {
			d = -d
		}
		s.JitterMs = s.JitterMs*0.875 + d*0.125
	}
	s.lastRTT = rttMs
	if s.RTTms == 0 {
		s.RTTms = rttMs
	} else {
		s.RTTms = s.RTTms*0.875 + rttMs*0.125
	}
	s.Recv++
}

func (s *GamingStats) RecordSent() { s.mu.Lock(); s.Sent++; s.mu.Unlock() }
func (s *GamingStats) RecordLost() {
	s.mu.Lock()
	s.Lost++
	if s.Sent > 0 {
		s.LossPct = float64(s.Lost) / float64(s.Sent) * 100
	}
	s.mu.Unlock()
}

// ShouldSwitch reports whether the current path is bad enough to move:
// RTT > 120 ms or loss > 3%.
func (s *GamingStats) ShouldSwitch() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RTTms > GamingRTTSwitchMs || s.LossPct > GamingLossSwitchPct
}

// Snapshot returns a copy of the scalar fields for metrics / the web
// panel. The mutex itself is never copied (vet: copylocks).
func (s *GamingStats) Snapshot() GamingStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return GamingStats{
		RTTms: s.RTTms, JitterMs: s.JitterMs, LossPct: s.LossPct,
		Sent: s.Sent, Recv: s.Recv, Lost: s.Lost,
		BestPath: s.BestPath, Switches: s.Switches, lastRTT: s.lastRTT,
	}
}

func (s *GamingStats) NoteSwitch(path string) {
	s.mu.Lock()
	s.BestPath = path
	s.Switches++
	s.mu.Unlock()
}

// ---- duplicate suppression -----------------------------------------------

// dedupReceiver drops repeated sequence numbers within a 1s window.
// Used by wg-gaming: the same datagram arrives twice (two subflows).
type dedupReceiver struct {
	mu   sync.Mutex
	seen map[uint32]time.Time
}

func newDedupReceiver() *dedupReceiver { return &dedupReceiver{seen: map[uint32]time.Time{}} }

// Seen returns true if seq was already delivered (duplicate).
func (d *dedupReceiver) Seen(seq uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if t, ok := d.seen[seq]; ok && now.Sub(t) < time.Second {
		return true
	}
	d.seen[seq] = now
	if len(d.seen) > 4096 {
		for k, t := range d.seen {
			if now.Sub(t) > time.Second {
				delete(d.seen, k)
			}
		}
	}
	return false
}

// ---- XOR FEC ---------------------------------------------------------------
// Tiny forward error correction: every group of dataShards payloads gets
// one parity shard (byte-wise XOR). Losing any single shard in the group
// is recoverable. wg-gaming uses dataShards=4 by default.

func xorFECEncode(shards [][]byte) []byte {
	max := 0
	for _, s := range shards {
		if len(s) > max {
			max = len(s)
		}
	}
	par := make([]byte, max)
	for _, s := range shards {
		for i, b := range s {
			par[i] ^= b
		}
	}
	return par
}

// xorFECRecover rebuilds the missing shard (index missing) from the
// surviving shards plus the parity shard. All shards are length-padded
// to the same size before the XOR.
func xorFECRecover(shards [][]byte, parity []byte, missing int) []byte {
	max := len(parity)
	out := make([]byte, max)
	copy(out, parity)
	for i, s := range shards {
		if i == missing {
			continue
		}
		for j := 0; j < len(s) && j < max; j++ {
			out[j] ^= s[j]
		}
	}
	return out
}

// ---- jitter buffer ---------------------------------------------------------
// jitterBuffer holds datagrams for a short, adaptive delay (5–15 ms) so
// network jitter does not reach the game as stutter. Game packets are
// released in sequence order once their release time passes.

type jitterBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []jbItem
	delay  time.Duration
	closed bool
}

type jbItem struct {
	seq     uint32
	data    []byte
	release time.Time
}

func newJitterBuffer(delay time.Duration) *jitterBuffer {
	j := &jitterBuffer{delay: delay}
	j.cond = sync.NewCond(&j.mu)
	return j
}

func (j *jitterBuffer) Push(seq uint32, data []byte) {
	j.mu.Lock()
	j.items = append(j.items, jbItem{seq: seq, data: data, release: time.Now().Add(j.delay)})
	j.cond.Broadcast()
	j.mu.Unlock()
}

// Release timing is enforced by Pop, which only returns items whose
// release time has passed; no background sweeper is needed.

// Pop returns the oldest due datagram, or false on timeout/close.
func (j *jitterBuffer) Pop(timeout time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(timeout)
	for {
		j.mu.Lock()
		now := time.Now()
		for i, it := range j.items {
			if !it.release.After(now) {
				data := it.data
				j.items = append(j.items[:i], j.items[i+1:]...)
				j.mu.Unlock()
				return data, true
			}
		}
		if j.closed || time.Now().After(deadline) {
			j.mu.Unlock()
			return nil, false
		}
		j.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
}

func (j *jitterBuffer) Close() {
	j.mu.Lock()
	j.closed = true
	j.cond.Broadcast()
	j.mu.Unlock()
}

// ---- small helpers ---------------------------------------------------------

func extraInt(extra map[string]string, key string, def int) int {
	if v := strings.TrimSpace(extra[key]); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func extraBool(extra map[string]string, key string, def bool) bool {
	if v := strings.TrimSpace(extra[key]); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}
