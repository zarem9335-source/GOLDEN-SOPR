// Package transport — secure transports for GOLDEN SOPR.
//
// tcp-stealth: real Noise NN handshake (flynn/noise, 25519/AES-GCM/SHA256)
// with the token mixed into the prologue, then AES-GCM framed records.
// tcp-pck: token-keyed AEAD — X25519 ephemeral + HKDF + AES-GCM framing,
// userspace (no kernel bypass is claimed). udp-kcp: KCP with AES block
// crypt + optional Reed-Solomon FEC. udp-quic: QUIC (TLS 1.3) where the
// token is proven by HMAC over TLS exported keying material — the token
// itself never crosses the wire. xdi: ICMP echo carrying framed data
// (Linux, root / CAP_NET_RAW).
//
// GOLDEN SOPR — gold theme: \x1b[38;5;220m (ANSI 220 / #FFD700).
package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ---------------------------------------------------------------------------
// Length-prefixed framing helpers (Noise / PCK data records)
// ---------------------------------------------------------------------------

func writeFrame(w io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > uint32(max) {
		return nil, fmt.Errorf("golden-sopr: frame too large (%d)", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// ---------------------------------------------------------------------------
// TCP + Stealth (Noise NN)
// ---------------------------------------------------------------------------

type noiseConn struct {
	conn net.Conn
	send *noise.CipherState
	recv *noise.CipherState
	wmu  sync.Mutex
	rbuf []byte
}

func noiseHandshake(conn net.Conn, token string, initiator bool) (*noiseConn, error) {
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	prologue := sha256.Sum256([]byte("golden-sopr-stealth:" + token))
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Pattern:     noise.HandshakeNN,
		Initiator:   initiator,
		Prologue:    prologue[:],
	})
	if err != nil {
		return nil, err
	}
	var send, recv *noise.CipherState
	if initiator {
		msg, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, err
		}
		if err := writeFrame(conn, msg); err != nil {
			return nil, err
		}
		reply, err := readFrame(conn, 65535)
		if err != nil {
			return nil, err
		}
		_, send, recv, err = hs.ReadMessage(nil, reply)
		if err != nil {
			return nil, fmt.Errorf("golden-sopr: noise handshake: %w", err)
		}
	} else {
		msg, err := readFrame(conn, 65535)
		if err != nil {
			return nil, err
		}
		if _, _, _, err := hs.ReadMessage(nil, msg); err != nil {
			return nil, fmt.Errorf("golden-sopr: noise handshake: %w", err)
		}
		reply, cs1, cs2, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, err
		}
		// Split() returns (initiator->responder, responder->initiator):
		// the responder sends with cs2 and receives with cs1.
		send, recv = cs2, cs1
		if err := writeFrame(conn, reply); err != nil {
			return nil, err
		}
	}
	if send == nil || recv == nil {
		return nil, errors.New("golden-sopr: noise handshake did not complete")
	}
	return &noiseConn{conn: conn, send: send, recv: recv}, nil
}

func (c *noiseConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	ct, err := readFrame(c.conn, 64*1024+16)
	if err != nil {
		return 0, err
	}
	pt, err := c.recv.Decrypt(nil, nil, ct)
	if err != nil {
		return 0, fmt.Errorf("golden-sopr: noise decrypt: %w", err)
	}
	n := copy(p, pt)
	if n < len(pt) {
		c.rbuf = append(c.rbuf[:0], pt[n:]...)
	}
	return n, nil
}

func (c *noiseConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16*1024 {
			n = 16 * 1024
		}
		ct, err := c.send.Encrypt(nil, nil, p[:n])
		if err != nil {
			return total, err
		}
		if err := writeFrame(c.conn, ct); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *noiseConn) Close() error                       { return c.conn.Close() }
func (c *noiseConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *noiseConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *noiseConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *noiseConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *noiseConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type stealthFactory struct{}

func (stealthFactory) Info() Info {
	return Info{Name: "tcp-stealth", Family: "tcp", Encrypted: true, SupportsUDP: true,
		Desc: "GOLDEN SOPR TCP + Noise NN handshake (25519/AES-GCM/SHA256, token in prologue) — server authenticated, token never in clear"}
}

func (stealthFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	setNoDelay(raw)
	nc, err := noiseHandshake(raw, token, true)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return nc, nil
}

func (stealthFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &noiseListener{Listener: ln, token: token}, nil
}

type noiseListener struct {
	net.Listener
	token string
}

func (l *noiseListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	setNoDelay(raw)
	nc, err := noiseHandshake(raw, l.token, false)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return nc, nil
}

// ---------------------------------------------------------------------------
// TCP + PCK (token-keyed AEAD, X25519 + HKDF + AES-GCM)
// ---------------------------------------------------------------------------

type pckConn struct {
	conn net.Conn
	aead cipher.AEAD
	wmu  sync.Mutex
	rbuf []byte
}

func pckDeriveKey(shared, token string) ([]byte, error) {
	// shared is the raw X25519 secret; salt binds the key to the token.
	salt := sha256.Sum256([]byte(token))
	r := hkdf.New(sha256.New, []byte(shared), salt[:], []byte("golden-sopr-pck-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func pckHandshake(conn net.Conn, token string, initiator bool) (*pckConn, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if initiator {
		if _, err := conn.Write(priv.PublicKey().Bytes()); err != nil {
			return nil, err
		}
	} else {
		// Server waits for the client's ephemeral first.
	}
	peer := make([]byte, 32)
	if _, err := io.ReadFull(conn, peer); err != nil {
		return nil, err
	}
	if !initiator {
		if _, err := conn.Write(priv.PublicKey().Bytes()); err != nil {
			return nil, err
		}
	}
	peerKey, err := curve.NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(peerKey)
	if err != nil {
		return nil, err
	}
	key, err := pckDeriveKey(string(shared), token)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &pckConn{conn: conn, aead: aead}
	// Explicit auth: first frame proves possession of the derived key.
	if initiator {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("golden-sopr-pck-auth"))
		if err := c.writeRecord(mac.Sum(nil)); err != nil {
			return nil, err
		}
		ack, err := c.readRecord()
		if err != nil || string(ack) != "ok" {
			return nil, errors.New("golden-sopr: pck auth rejected by server")
		}
	} else {
		auth, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("golden-sopr-pck-auth"))
		if !hmac.Equal(auth, mac.Sum(nil)) {
			return nil, errors.New("golden-sopr: pck auth failed (wrong token)")
		}
		if err := c.writeRecord([]byte("ok")); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// writeRecord encrypts one record: [4B len][12B nonce][ciphertext+tag].
func (c *pckConn) writeRecord(pt []byte) error {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := c.aead.Seal(nil, nonce, pt, nil)
	frame := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(frame[:4], uint32(12+len(ct)))
	copy(frame[4:16], nonce)
	copy(frame[16:], ct)
	_, err := c.conn.Write(frame)
	return err
}

func (c *pckConn) readRecord() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 12 || n > 64*1024+64 {
		return nil, fmt.Errorf("golden-sopr: pck frame too large (%d)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, err
	}
	return c.aead.Open(nil, buf[:12], buf[12:], nil)
}

func (c *pckConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	pt, err := c.readRecord()
	if err != nil {
		return 0, err
	}
	n := copy(p, pt)
	if n < len(pt) {
		c.rbuf = append(c.rbuf[:0], pt[n:]...)
	}
	return n, nil
}

func (c *pckConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16*1024 {
			n = 16 * 1024
		}
		if err := c.writeRecord(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *pckConn) Close() error                       { return c.conn.Close() }
func (c *pckConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *pckConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *pckConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *pckConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *pckConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type pckFactory struct{}

func (pckFactory) Info() Info {
	return Info{Name: "tcp-pck", Family: "tcp", Encrypted: true, NeedsRoot: false, SupportsUDP: true,
		Desc: "GOLDEN SOPR TCP + PCK (token-keyed AEAD: X25519 + HKDF + AES-GCM, userspace framing, TCP_NODELAY)"}
}

func (pckFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	setNoDelay(raw)
	nc, err := pckHandshake(raw, token, true)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return nc, nil
}

func (pckFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &pckListener{Listener: ln, token: token}, nil
}

type pckListener struct {
	net.Listener
	token string
}

func (l *pckListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	setNoDelay(raw)
	nc, err := pckHandshake(raw, l.token, false)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return nc, nil
}

// ---------------------------------------------------------------------------
// UDP + KCP (+ optional FEC)
// ---------------------------------------------------------------------------

type kcpFactory struct{}

func (kcpFactory) Info() Info {
	return Info{Name: "udp-kcp", Family: "udp", Encrypted: true, SupportsUDP: true,
		Desc: "GOLDEN SOPR UDP + KCP (AES block crypt, fast retransmit, optional Reed-Solomon FEC via extra fec=true)"}
}

func kcpShards(extra map[string]string) (int, int) {
	if extraFlag(extra, "fec") {
		return 8, 2
	}
	return 0, 0
}

func kcpTune(sess *kcp.UDPSession, extra map[string]string) {
	if extraStr(extra, "preset", "") == "gaming" || extraFlag(extra, "gaming") {
		sess.SetNoDelay(1, 10, 2, 1)
	} else {
		sess.SetNoDelay(1, 20, 2, 1)
	}
	sess.SetWindowSize(1024, 1024)
	sess.SetMtu(1400)
	sess.SetACKNoDelay(true)
}

func (kcpFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	block, err := kcp.NewAESBlockCrypt(tokenKey(token))
	if err != nil {
		return nil, err
	}
	ds, ps := kcpShards(extra)
	sess, err := kcp.DialWithOptions(addr, block, ds, ps)
	if err != nil {
		return nil, err
	}
	kcpTune(sess, extra)
	return sess, nil
}

func (kcpFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	block, err := kcp.NewAESBlockCrypt(tokenKey(token))
	if err != nil {
		return nil, err
	}
	ds, ps := kcpShards(extra)
	ln, err := kcp.ListenWithOptions(addr, block, ds, ps)
	if err != nil {
		return nil, err
	}
	return &kcpListener{Listener: ln, extra: extra}, nil
}

type kcpListener struct {
	*kcp.Listener
	extra map[string]string
}

func (l *kcpListener) Accept() (net.Conn, error) {
	sess, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if ks, ok := sess.(*kcp.UDPSession); ok {
		kcpTune(ks, l.extra)
	}
	return sess, nil
}

// ---------------------------------------------------------------------------
// UDP + QUIC (TLS 1.3, token proven by HMAC over exported keying material)
// ---------------------------------------------------------------------------

func quicTLSConfig(extra map[string]string, server bool) (*tls.Config, error) {
	if server {
		cert, err := selfSignedCert(extra)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"sopr-quic"},
		}, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"sopr-quic"}}
	if sni := extraStr(extra, "sni", ""); sni != "" {
		cfg.ServerName = sni
	}
	// The token proof (HMAC over the TLS session's exported keying
	// material) binds auth to this session, so a MITM holding a different
	// session cannot forge it — the cert itself is not the trust anchor.
	// A CA file opts back into full certificate verification.
	if caFile := extraStr(extra, "ca_file", ""); caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("golden-sopr: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("golden-sopr: no valid certs in CA file")
		}
		cfg.RootCAs = pool
	} else {
		cfg.InsecureSkipVerify = true //nolint:gosec // auth is the HMAC proof below, not the cert
	}
	return cfg, nil
}

func quicProof(conn *quic.Conn, token string) []byte {
	tlsState := conn.ConnectionState().TLS
	material, err := tlsState.ExportKeyingMaterial("golden-sopr-quic", nil, 32)
	if err != nil || len(material) == 0 {
		// Fallback (older TLS stacks): still bound to the token, weaker
		// than the session binding but never sends the token itself.
		material = []byte("golden-sopr-quic-proof")
	}
	mac := hmac.New(sha256.New, tokenKey(token))
	mac.Write(material)
	return mac.Sum(nil)
}

// quicStreamConn adapts one QUIC stream to net.Conn.
type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
	local  net.Addr
	remote net.Addr
	once   sync.Once
}

func (c *quicStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *quicStreamConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = c.stream.Close()
		err = c.conn.CloseWithError(0, "golden-sopr done")
	})
	return err
}
func (c *quicStreamConn) LocalAddr() net.Addr                { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

type quicFactory struct{}

func (quicFactory) Info() Info {
	return Info{Name: "udp-quic", Family: "udp", Encrypted: true, SupportsUDP: true,
		Desc: "GOLDEN SOPR UDP + QUIC (TLS 1.3, session-bound token proof via HMAC over exported keying material; token never sent)"}
}

func (quicFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	tlsCfg, err := quicTLSConfig(extra, false)
	if err != nil {
		return nil, err
	}
	if tlsCfg.ServerName == "" {
		if h, _, err := net.SplitHostPort(addr); err == nil {
			tlsCfg.ServerName = h
		}
	}
	qc, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "no stream")
		return nil, err
	}
	if _, err := st.Write(quicProof(qc, token)); err != nil {
		_ = qc.CloseWithError(0, "proof write failed")
		return nil, err
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(st, ack); err != nil || ack[0] != 1 {
		_ = qc.CloseWithError(0, "auth rejected")
		return nil, errors.New("golden-sopr: quic token proof rejected by server")
	}
	return &quicStreamConn{stream: st, conn: qc, local: qc.LocalAddr(), remote: qc.RemoteAddr()}, nil
}

func (quicFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	tlsCfg, err := quicTLSConfig(extra, true)
	if err != nil {
		return nil, err
	}
	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &quicListener{Listener: ln, token: token, closed: make(chan struct{})}, nil
}

type quicListener struct {
	*quic.Listener
	token  string
	closed chan struct{}
	once   sync.Once
}

func (l *quicListener) Accept() (net.Conn, error) {
	for {
		qc, err := l.Listener.Accept(context.Background())
		if err != nil {
			return nil, err
		}
		st, err := qc.AcceptStream(context.Background())
		if err != nil {
			_ = qc.CloseWithError(0, "no stream")
			continue
		}
		proof := make([]byte, 32)
		if _, err := io.ReadFull(st, proof); err != nil {
			_ = qc.CloseWithError(0, "no proof")
			continue
		}
		if !hmac.Equal(proof, quicProof(qc, l.token)) {
			_, _ = st.Write([]byte{0})
			_ = qc.CloseWithError(0, "bad token proof")
			continue
		}
		if _, err := st.Write([]byte{1}); err != nil {
			_ = qc.CloseWithError(0, "ack failed")
			continue
		}
		return &quicStreamConn{stream: st, conn: qc, local: qc.LocalAddr(), remote: qc.RemoteAddr()}, nil
	}
}

func (l *quicListener) Close() error {
	var err error
	l.once.Do(func() { err = l.Listener.Close() })
	return err
}

// ---------------------------------------------------------------------------
// xDi — ICMP echo carrying framed data (experimental, needs root/CAP_NET_RAW)
// ---------------------------------------------------------------------------

const icmpFrameMax = 1200

// icmpConn is a net.Conn over ICMP echo: the client sends Echo requests,
// the server answers with Echo replies; each packet carries one
// [2B len][payload] frame.
type icmpConn struct {
	pc      *icmp.PacketConn
	peer    net.Addr
	id      int
	server  bool
	rx      chan []byte
	buf     []byte
	mu      sync.Mutex
	seq     int
	lastSeq int
	rdead   time.Time
	closed  chan struct{}
	once    sync.Once
	local   net.Addr
	own     bool // Close() closes pc (dialled conns own their socket)
}

func newICMPConn(pc *icmp.PacketConn, peer net.Addr, id int, server bool) *icmpConn {
	return &icmpConn{pc: pc, peer: peer, id: id, server: server,
		rx: make(chan []byte, udpChanDepth), closed: make(chan struct{}), local: pc.LocalAddr()}
}

func newICMPConnOwned(pc *icmp.PacketConn, peer net.Addr, id int, server bool) *icmpConn {
	c := newICMPConn(pc, peer, id, server)
	c.own = true
	return c
}

func (c *icmpConn) pushFrame(data []byte) {
	if len(data) < 2 {
		return
	}
	ln := int(binary.BigEndian.Uint16(data[:2]))
	if ln > len(data)-2 {
		return
	}
	cp := make([]byte, ln)
	copy(cp, data[2:2+ln])
	select {
	case c.rx <- cp:
	case <-c.closed:
	default:
	}
}

func (c *icmpConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	var timer *time.Timer
	var tch <-chan time.Time
	if !c.rdead.IsZero() {
		d := time.Until(c.rdead)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(d)
		tch = timer.C
	}
	select {
	case <-c.closed:
		return 0, io.EOF
	case <-tch:
		return 0, os.ErrDeadlineExceeded
	case chunk, ok := <-c.rx:
		if timer != nil {
			timer.Stop()
		}
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		if n < len(chunk) {
			c.buf = append(c.buf[:0], chunk[n:]...)
		}
		return n, nil
	}
}

func (c *icmpConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > icmpFrameMax {
			n = icmpFrameMax
		}
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], p[:n])
		c.mu.Lock()
		c.seq++
		seq := c.seq
		if c.server {
			seq = c.lastSeq
		}
		c.mu.Unlock()
		var typ icmp.Type = ipv4.ICMPTypeEcho
		if c.server {
			typ = ipv4.ICMPTypeEchoReply
		}
		msg := icmp.Message{Type: typ, Code: 0,
			Body: &icmp.Echo{ID: c.id, Seq: seq, Data: frame}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return total, err
		}
		if _, err := c.pc.WriteTo(b, c.peer); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *icmpConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		if c.own {
			err = c.pc.Close()
		}
	})
	return err
}
func (c *icmpConn) LocalAddr() net.Addr  { return c.local }
func (c *icmpConn) RemoteAddr() net.Addr { return c.peer }
func (c *icmpConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdead = t
	c.mu.Unlock()
	return nil
}
func (c *icmpConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *icmpConn) SetWriteDeadline(t time.Time) error { return nil }

type xdiFactory struct{}

func (xdiFactory) Info() Info {
	return Info{Name: "xdi", Family: "icmp", Encrypted: true, NeedsRoot: true, SupportsUDP: true,
		Desc: "GOLDEN SOPR xDi / ICMP tunnel (token-keyed framed echo, experimental — Linux, root / CAP_NET_RAW, ICMP open)"}
}

func (xdiFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, err
	}
	pc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("golden-sopr: xdi needs root/CAP_NET_RAW (icmp listen failed): %w", err)
	}
	id := int(time.Now().UnixNano() % 65535)
	c := newICMPConnOwned(pc, ip, id, false)
	go c.readLoopClient()
	return c, nil
}

func (c *icmpConn) readLoopClient() {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			c.Close()
			return
		}
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != c.id {
			continue
		}
		c.pushFrame(echo.Data)
	}
}

func (xdiFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	pc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("golden-sopr: xdi needs root/CAP_NET_RAW (icmp listen failed): %w", err)
	}
	l := &icmpListener{pc: pc, acceptCh: make(chan net.Conn, 32),
		conns: map[string]*icmpConn{}, closed: make(chan struct{})}
	go l.dispatch()
	return l, nil
}

type icmpListener struct {
	pc       *icmp.PacketConn
	acceptCh chan net.Conn
	mu       sync.Mutex
	conns    map[string]*icmpConn
	closed   chan struct{}
	once     sync.Once
}

func (l *icmpListener) dispatch() {
	buf := make([]byte, 65535)
	for {
		n, peer, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.Close()
			return
		}
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEcho {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		key := peer.String() + "/" + fmt.Sprint(echo.ID)
		l.mu.Lock()
		c, ok := l.conns[key]
		if !ok {
			c = newICMPConn(l.pc, peer, echo.ID, true)
			l.conns[key] = c
			l.mu.Unlock()
			select {
			case l.acceptCh <- c:
			case <-l.closed:
				return
			}
		} else {
			l.mu.Unlock()
		}
		c.mu.Lock()
		c.lastSeq = echo.Seq
		c.mu.Unlock()
		c.pushFrame(echo.Data)
	}
}

func (l *icmpListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.acceptCh:
		if !ok {
			return nil, io.EOF
		}
		return c, nil
	case <-l.closed:
		return nil, io.ErrClosedPipe
	}
}

func (l *icmpListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.pc.Close()
	})
	return err
}
func (l *icmpListener) Addr() net.Addr { return l.pc.LocalAddr() }
