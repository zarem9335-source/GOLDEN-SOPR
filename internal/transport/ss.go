// GOLDEN SOPR — "ss" transport: Shadowsocks AEAD (AES-256-GCM).
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// TCP mode (default): 32-byte random salt, then AEAD frames
// [enc(len 2)][enc(payload)] with subkey = HKDF-SHA1(SHA256(token),
// salt, "ss-subkey") and a 12-byte little-endian counter nonce.
// UDP mode (extra ss_udp=1): each datagram is salt + AEAD(address +
// payload), one fresh salt per datagram, as in Shadowsocks UDP relay.
// Master key is SHA256(token); no password is ever sent in the clear.
package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

type ssFactory struct{}

func (f *ssFactory) Info() Info {
	return Info{
		Name:        "ss",
		Family:      "tcp",
		Encrypted:   true,
		NeedsRoot:   false,
		SupportsUDP: true,
		Desc:        "Shadowsocks AEAD (AES-256-GCM, HKDF subkeys, random salt). TCP framed mode by default; ss_udp=1 for datagram mode. Blends with ordinary Shadowsocks traffic.",
	}
}

func ssMasterKey(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func ssSubkey(master, salt []byte) ([]byte, error) {
	h := hkdf.New(sha1.New, master, salt, []byte("ss-subkey"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ssAEAD is one direction of the Shadowsocks AEAD stream cipher.
type ssAEAD struct {
	aead    cipher.AEAD
	counter uint64
}

func newSSAEADKey(key []byte) (*ssAEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &ssAEAD{aead: aead}, nil
}

func (s *ssAEAD) nonce() []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint64(n, s.counter)
	s.counter++
	return n
}

func (s *ssAEAD) seal(plain []byte) []byte { return s.aead.Seal(nil, s.nonce(), plain, nil) }

func (s *ssAEAD) open(ct []byte) ([]byte, error) {
	return s.aead.Open(nil, s.nonce(), ct, nil)
}

// ssConn: AEAD-framed stream over a TCP connection.
type ssConn struct {
	c       net.Conn
	enc     *ssAEAD
	dec     *ssAEAD
	mu      sync.Mutex // serialises Write
	readBuf []byte
}

func (c *ssConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		// One frame: enc(2-byte length) then enc(payload).
		lenCt := make([]byte, 2+16)
		if _, err := io.ReadFull(c.c, lenCt); err != nil {
			return 0, err
		}
		lnBytes, err := c.dec.open(lenCt)
		if err != nil {
			return 0, fmt.Errorf("ss: bad length chunk: %w", err)
		}
		ln := int(binary.BigEndian.Uint16(lnBytes))
		if ln < 0 || ln > 16383 {
			return 0, errors.New("ss: bad frame length")
		}
		ct := make([]byte, ln+16)
		if _, err := io.ReadFull(c.c, ct); err != nil {
			return 0, err
		}
		plain, err := c.dec.open(ct)
		if err != nil {
			return 0, fmt.Errorf("ss: bad payload chunk: %w", err)
		}
		c.readBuf = plain
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *ssConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16383 {
			n = 16383
		}
		chunk := p[:n]
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(n))
		frame := append(c.enc.seal(lb[:]), c.enc.seal(chunk)...)
		if _, err := c.c.Write(frame); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (c *ssConn) Close() error                  { return c.c.Close() }
func (c *ssConn) LocalAddr() net.Addr           { return c.c.LocalAddr() }
func (c *ssConn) RemoteAddr() net.Addr          { return c.c.RemoteAddr() }
func (c *ssConn) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }
func (c *ssConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}
func (c *ssConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

func (f *ssFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	if extraBool(extra, "ss_udp", false) {
		return ssDialUDP(ctx, addr, token, extra)
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		raw.Close()
		return nil, err
	}
	key, err := ssSubkey(ssMasterKey(token), salt)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := raw.Write(salt); err != nil {
		raw.Close()
		return nil, err
	}
	enc, err := newSSAEADKey(key)
	if err != nil {
		raw.Close()
		return nil, err
	}
	dec, err := newSSAEADKey(key)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return &ssConn{c: raw, enc: enc, dec: dec}, nil
}

func (f *ssFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	if extraBool(extra, "ss_udp", false) {
		return ssListenUDP(ctx, addr, token, extra)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &ssListener{ln: ln, token: token, ctx: ctx}, nil
}

type ssListener struct {
	ln    net.Listener
	token string
	ctx   context.Context
}

func (l *ssListener) Accept() (net.Conn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(raw, salt); err != nil {
		raw.Close()
		return nil, err
	}
	key, err := ssSubkey(ssMasterKey(l.token), salt)
	if err != nil {
		raw.Close()
		return nil, err
	}
	enc, err := newSSAEADKey(key)
	if err != nil {
		raw.Close()
		return nil, err
	}
	dec, err := newSSAEADKey(key)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return &ssConn{c: raw, enc: enc, dec: dec}, nil
}

func (l *ssListener) Close() error   { return l.ln.Close() }
func (l *ssListener) Addr() net.Addr { return l.ln.Addr() }

// ---- UDP datagram mode ----------------------------------------------------
// Each datagram: [salt 32][AEAD(address + payload)], fresh salt per
// datagram. Address header: 0x01 + 4-byte IPv4 + 2-byte port, or
// 0x03 + len + domain + port, or 0x04 + 16-byte IPv6 + port.

func ssUDPAddrHeader(addr *net.UDPAddr) []byte {
	if ip4 := addr.IP.To4(); ip4 != nil {
		out := []byte{0x01}
		out = append(out, ip4...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], uint16(addr.Port))
		return append(out, pb[:]...)
	}
	out := []byte{0x04}
	out = append(out, addr.IP.To16()...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(addr.Port))
	return append(out, pb[:]...)
}

type ssUDPConn struct {
	pc    *net.UDPConn
	token string
	mu    sync.Mutex
	// Server side only: the peer this conn serves, its inbound queue and
	// its close channel. Client conns leave these nil and read the socket.
	peer    *net.UDPAddr
	inbound chan []byte
	done    chan struct{}
}

func ssDialUDP(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	return &ssUDPConn{pc: pc, token: token, done: make(chan struct{})}, nil
}

func ssListenUDP(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return &ssUDPListener{pc: pc, token: token, acceptCh: make(chan net.Conn, 16), done: make(chan struct{})}, nil
}

// ssUDPListener accepts one datagram flow per remote peer.
type ssUDPListener struct {
	pc       *net.UDPConn
	token    string
	acceptCh chan net.Conn
	done     chan struct{}
	once     sync.Once
	seen     sync.Map // addr string -> *ssUDPConn (server side, per peer)
}

func (l *ssUDPListener) Accept() (net.Conn, error) {
	// Server-side UDP is connectionless: synthesise a conn per peer on
	// first datagram. A background reader demultiplexes by source addr.
	go l.readLoop()
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.done:
		return nil, errors.New("ss udp listener closed")
	}
}

func (l *ssUDPListener) readLoop() {
	tmp := make([]byte, 65535)
	for {
		n, src, err := l.pc.ReadFromUDP(tmp)
		if err != nil {
			return
		}
		if n < 32+16 {
			continue
		}
		salt := tmp[:32]
		key, err := ssSubkey(ssMasterKey(l.token), salt)
		if err != nil {
			continue
		}
		aead, err := newSSAEADKey(key)
		if err != nil {
			continue
		}
		plain, err := aead.open(tmp[32:n])
		if err != nil || len(plain) < 1 {
			continue
		}
		// Strip the address header.
		hdrLen := 0
		switch plain[0] {
		case 0x01:
			hdrLen = 1 + 4 + 2
		case 0x03:
			if len(plain) < 2 {
				continue
			}
			hdrLen = 1 + 1 + int(plain[1]) + 2
		case 0x04:
			hdrLen = 1 + 16 + 2
		default:
			continue
		}
		if len(plain) < hdrLen {
			continue
		}
		peerKey := src.String()
		v, loaded := l.seen.LoadOrStore(peerKey, &ssUDPConn{pc: l.pc, token: l.token, peer: src, inbound: make(chan []byte, 64), done: make(chan struct{})})
		sc := v.(*ssUDPConn)
		if !loaded {
			select {
			case l.acceptCh <- sc:
			case <-l.done:
				return
			}
		}
		payload := append([]byte(nil), plain[hdrLen:]...)
		select {
		case sc.inbound <- payload:
		default:
		}
	}
}

func (l *ssUDPListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.pc.Close()
	})
	return err
}

func (l *ssUDPListener) Addr() net.Addr { return l.pc.LocalAddr() }

func (c *ssUDPConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	key, err := ssSubkey(ssMasterKey(c.token), salt)
	if err != nil {
		return 0, err
	}
	aead, err := newSSAEADKey(key)
	if err != nil {
		return 0, err
	}
	var target *net.UDPAddr
	if c.peer != nil {
		target = c.peer
	} else if ua, ok := c.pc.RemoteAddr().(*net.UDPAddr); ok {
		target = ua
	} else {
		return 0, errors.New("ss udp: no remote addr")
	}
	plain := append(ssUDPAddrHeader(target), p...)
	ct := aead.seal(plain)
	pkt := append(append([]byte(nil), salt...), ct...)
	if c.peer != nil {
		_, err = c.pc.WriteToUDP(pkt, c.peer)
	} else {
		_, err = c.pc.Write(pkt)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns one decrypted datagram payload (client: direct socket read;
// server: demultiplexed inbound channel).
func (c *ssUDPConn) Read(p []byte) (int, error) {
	if c.inbound != nil {
		select {
		case data := <-c.inbound:
			return copy(p, data), nil
		case <-c.done:
			return 0, io.ErrClosedPipe
		}
	}
	tmp := make([]byte, 65535)
	n, err := c.pc.Read(tmp)
	if err != nil {
		return 0, err
	}
	if n < 32+16 {
		return 0, errors.New("ss udp: short datagram")
	}
	key, err := ssSubkey(ssMasterKey(c.token), tmp[:32])
	if err != nil {
		return 0, err
	}
	aead, err := newSSAEADKey(key)
	if err != nil {
		return 0, err
	}
	plain, err := aead.open(tmp[32:n])
	if err != nil {
		return 0, err
	}
	// Strip the Shadowsocks address header the peer prepended.
	hdrLen, err := ssAddrHeaderLen(plain)
	if err != nil {
		return 0, err
	}
	return copy(p, plain[hdrLen:]), nil
}

// ssAddrHeaderLen returns the length of the address header at the start
// of a decrypted Shadowsocks UDP payload.
func ssAddrHeaderLen(plain []byte) (int, error) {
	if len(plain) < 1 {
		return 0, errors.New("ss udp: empty payload")
	}
	switch plain[0] {
	case 0x01:
		if len(plain) < 7 {
			return 0, errors.New("ss udp: short ipv4 header")
		}
		return 7, nil
	case 0x03:
		if len(plain) < 2 {
			return 0, errors.New("ss udp: short domain header")
		}
		if len(plain) < 1+1+int(plain[1])+2 {
			return 0, errors.New("ss udp: short domain header")
		}
		return 1 + 1 + int(plain[1]) + 2, nil
	case 0x04:
		if len(plain) < 19 {
			return 0, errors.New("ss udp: short ipv6 header")
		}
		return 19, nil
	}
	return 0, errors.New("ss udp: bad address type")
}

func (c *ssUDPConn) Close() error {
	if c.done != nil {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
	if c.peer == nil {
		return c.pc.Close()
	}
	return nil // server-side peer conns share the listener socket
}
func (c *ssUDPConn) LocalAddr() net.Addr { return c.pc.LocalAddr() }
func (c *ssUDPConn) RemoteAddr() net.Addr {
	if c.peer != nil {
		return c.peer
	}
	return c.pc.RemoteAddr()
}
func (c *ssUDPConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *ssUDPConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *ssUDPConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
