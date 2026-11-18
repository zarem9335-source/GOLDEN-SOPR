// Package transport — classic transports for GOLDEN SOPR.
//
// tcp / tcp-mux: raw TCP (muxing is done by smux in core, so tcp-mux is the
// same wire with a different pool policy). udp: length-prefixed frames over
// UDP. ws / ws-mux / wss / wss-mux: WebSocket (plain or TLS) with a net.Conn
// adapter over gorilla/websocket binary messages.
//
// GOLDEN SOPR — gold theme: \x1b[38;5;220m (ANSI 220 / #FFD700).
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// tokenKey derives a 32-byte key from the tunnel token (SHA-256).
func tokenKey(token string) []byte {
	sum := sha256.Sum256([]byte("golden-sopr:" + token))
	return sum[:]
}

func extraStr(extra map[string]string, key, def string) string {
	if extra != nil {
		if v, ok := extra[key]; ok && v != "" {
			return v
		}
	}
	return def
}

func extraFlag(extra map[string]string, key string) bool {
	if extra == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(extra[key]))
	return v == "true" || v == "1" || v == "yes"
}

func setNoDelay(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// selfSignedCert generates an in-memory self-signed ECDSA certificate for
// the WSS / QUIC server when no cert/key files are configured.
// CN is "golden-sopr" so the cert is recognisable in logs.
func selfSignedCert(extra map[string]string) (tls.Certificate, error) {
	host := extraStr(extra, "sni", "golden-sopr")
	if host == "" {
		host = "golden-sopr"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"GOLDEN SOPR"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{host, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// tlsConfigForServer returns a server TLS config: files from extra
// (cert/key) when present, otherwise a fresh self-signed certificate.
func tlsConfigForServer(extra map[string]string) (*tls.Config, error) {
	certFile, keyFile := extraStr(extra, "cert", ""), extraStr(extra, "key", "")
	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("golden-sopr: load TLS cert: %w", err)
		}
	} else {
		cert, err = selfSignedCert(extra)
		if err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// tlsConfigForClient returns a client TLS config. Verification stays ON
// unless extra insecure=true (self-signed deployments) or a CA file is given.
func tlsConfigForClient(extra map[string]string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if sni := extraStr(extra, "sni", ""); sni != "" {
		cfg.ServerName = sni
	}
	if extraFlag(extra, "insecure") {
		cfg.InsecureSkipVerify = true //nolint:gosec // explicit user opt-in for self-signed
		return cfg, nil
	}
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
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// TCP / TCP-Mux
// ---------------------------------------------------------------------------

type tcpFactory struct{ mux bool }

func (f tcpFactory) Info() Info {
	if f.mux {
		return Info{Name: "tcp-mux", Family: "tcp", Encrypted: false, SupportsUDP: true,
			Desc: "GOLDEN SOPR TCP with smux multiplexing (core smux; one TCP conn carries many streams)"}
	}
	return Info{Name: "tcp", Family: "tcp", Encrypted: false, SupportsUDP: true,
		Desc: "GOLDEN SOPR plain TCP reverse tunnel (simplest; token sent in clear — use an encrypted transport on untrusted paths)"}
}

func (f tcpFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	setNoDelay(c)
	return c, nil
}

func (f tcpFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// ---------------------------------------------------------------------------
// UDP — length-prefixed framed stream over UDP datagrams
// ---------------------------------------------------------------------------

const (
	udpFrameMax  = 1400 // payload bytes per datagram (stays under common MTUs)
	udpChanDepth = 128
)

// udpConn is a net.Conn over UDP: Write splits into 2-byte-len frames,
// Read reassembles them into a byte stream.
type udpConn struct {
	pc        *net.UDPConn
	remote    *net.UDPAddr // nil for dialled (connected) conns
	own       bool         // Close() closes pc
	rx        chan []byte
	buf       []byte
	mu        sync.Mutex
	rdead     time.Time
	wdead     time.Time
	closed    chan struct{}
	closeOnce sync.Once
	local     net.Addr
}

func newUDPConn(pc *net.UDPConn, remote *net.UDPAddr, own bool) *udpConn {
	return &udpConn{pc: pc, remote: remote, own: own, rx: make(chan []byte, udpChanDepth),
		closed: make(chan struct{}), local: pc.LocalAddr()}
}

// push is called by the read loop / dispatcher with one decoded payload.
func (c *udpConn) push(p []byte) {
	select {
	case c.rx <- p:
	case <-c.closed:
	default:
		// Channel full: drop oldest-ish (UDP is lossy by nature; core
		// retransmits at a higher layer for KCP, TCP flows use smux).
	}
}

func (c *udpConn) Read(p []byte) (int, error) {
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

func (c *udpConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	_ = c.pc.SetWriteDeadline(c.wdead)
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > udpFrameMax {
			n = udpFrameMax
		}
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], p[:n])
		var err error
		if c.remote != nil {
			_, err = c.pc.WriteToUDP(frame, c.remote)
		} else {
			_, err = c.pc.Write(frame)
		}
		if err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *udpConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.own {
			err = c.pc.Close()
		}
	})
	return err
}
func (c *udpConn) LocalAddr() net.Addr { return c.local }
func (c *udpConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.pc.RemoteAddr()
}
func (c *udpConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdead, c.wdead = t, t
	c.mu.Unlock()
	return nil
}
func (c *udpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdead = t
	c.mu.Unlock()
	return nil
}
func (c *udpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdead = t
	c.mu.Unlock()
	return nil
}

// readLoop pumps datagrams from pc into conn (dialled / connected case).
func (c *udpConn) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := c.pc.Read(buf)
		if err != nil {
			c.Close()
			return
		}
		if n < 2 {
			continue
		}
		ln := int(binary.BigEndian.Uint16(buf[:2]))
		if ln > n-2 {
			continue
		}
		cp := make([]byte, ln)
		copy(cp, buf[2:2+ln])
		c.push(cp)
	}
}

type udpFactory struct{}

func (udpFactory) Info() Info {
	return Info{Name: "udp", Family: "udp", Encrypted: false, SupportsUDP: true,
		Desc: "GOLDEN SOPR plain UDP reverse tunnel (length-prefixed frames; needs UDP open)"}
}

func (udpFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return nil, err
	}
	c := newUDPConn(pc, nil, true)
	go c.readLoop()
	return c, nil
}

func (udpFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	l := &udpListener{pc: pc, acceptCh: make(chan net.Conn, 32),
		conns: map[string]*udpConn{}, closed: make(chan struct{})}
	go l.dispatch()
	return l, nil
}

// udpListener demultiplexes datagrams by peer address into per-peer udpConns.
type udpListener struct {
	pc       *net.UDPConn
	acceptCh chan net.Conn
	mu       sync.Mutex
	conns    map[string]*udpConn
	closed   chan struct{}
	once     sync.Once
}

func (l *udpListener) dispatch() {
	buf := make([]byte, 65535)
	for {
		n, peer, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			l.Close()
			return
		}
		if n < 2 {
			continue
		}
		ln := int(binary.BigEndian.Uint16(buf[:2]))
		if ln > n-2 {
			continue
		}
		payload := make([]byte, ln)
		copy(payload, buf[2:2+ln])
		key := peer.String()
		l.mu.Lock()
		c, ok := l.conns[key]
		if !ok {
			c = newUDPConn(l.pc, peer, false)
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
		c.push(payload)
	}
}

func (l *udpListener) Accept() (net.Conn, error) {
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

func (l *udpListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.pc.Close()
	})
	return err
}
func (l *udpListener) Addr() net.Addr { return l.pc.LocalAddr() }

// ---------------------------------------------------------------------------
// WebSocket / WSS — net.Conn adapter over gorilla/websocket binary messages
// ---------------------------------------------------------------------------

// wsConn adapts *websocket.Conn to net.Conn.
type wsConn struct {
	conn   *websocket.Conn
	wmu    sync.Mutex
	buf    []byte
	done   chan struct{}
	once   sync.Once
	closed bool
}

func newWSConn(c *websocket.Conn) *wsConn {
	return &wsConn{conn: c, done: make(chan struct{})}
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	// Skip non-binary frames (ping/pong are handled by gorilla).
	for {
		mt, msg, err := c.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		n := copy(p, msg)
		if n < len(msg) {
			c.buf = append(c.buf[:0], msg[n:]...)
		}
		return n, nil
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// Chunk so one smux frame does not become a giant WS message.
	const chunk = 32 * 1024
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		if err := c.conn.WriteMessage(websocket.BinaryMessage, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *wsConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		err = c.conn.Close()
	})
	return err
}
func (c *wsConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// wsListener is a net.Listener that upgrades HTTP connections to WebSocket.
type wsListener struct {
	ln       net.Listener
	srv      *http.Server
	acceptCh chan net.Conn
	closed   chan struct{}
	once     sync.Once
	path     string
}

func newWSListener(ln net.Listener, path string) *wsListener {
	l := &wsListener{ln: ln, acceptCh: make(chan net.Conn, 32),
		closed: make(chan struct{}), path: path}
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true },
		ReadBufferSize: 32 * 1024, WriteBufferSize: 32 * 1024}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := newWSConn(ws)
		select {
		case l.acceptCh <- c:
			<-c.done // keep handler alive until the WS conn closes
		case <-l.closed:
			_ = ws.Close()
		}
	})
	l.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l
}

func (l *wsListener) Accept() (net.Conn, error) {
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
func (l *wsListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.srv.Close()
		_ = l.ln.Close()
	})
	return err
}
func (l *wsListener) Addr() net.Addr { return l.ln.Addr() }

func wsPath(extra map[string]string) string {
	p := extraStr(extra, "path", "/sopr")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func wsDialURL(scheme, addr string, extra map[string]string) string {
	host := addr
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	return scheme + "://" + host + wsPath(extra)
}

type wsFactory struct {
	mux bool
	tls bool
}

func (f wsFactory) Info() Info {
	name := "ws"
	if f.tls {
		name = "wss"
	}
	if f.mux {
		name += "-mux"
	}
	enc := f.tls
	desc := "GOLDEN SOPR WebSocket reverse tunnel"
	if f.tls {
		desc += " over TLS (certificate required; token protected by TLS)"
	}
	if f.mux {
		desc += " with smux multiplexing"
	}
	return Info{Name: name, Family: "ws", Encrypted: enc, SupportsUDP: true, NeedsCert: f.tls, Desc: desc}
}

func (f wsFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	scheme := "ws"
	dialer := &websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	if f.tls {
		scheme = "wss"
		tlsCfg, err := tlsConfigForClient(extra)
		if err != nil {
			return nil, err
		}
		if tlsCfg.ServerName == "" {
			if h, _, err := net.SplitHostPort(addr); err == nil {
				tlsCfg.ServerName = h
			}
		}
		dialer.TLSClientConfig = tlsCfg
	}
	ws, _, err := dialer.DialContext(ctx, wsDialURL(scheme, addr, extra), nil)
	if err != nil {
		return nil, err
	}
	return newWSConn(ws), nil
}

func (f wsFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if f.tls {
		tlsCfg, err := tlsConfigForServer(extra)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, tlsCfg)
	}
	return newWSListener(ln, wsPath(extra)), nil
}
