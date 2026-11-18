// GOLDEN SOPR — "hq" transport: QUIC + WebSocket-style multiplex (HTTP/3 style).
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// One QUIC connection (ALPN "sopr-hq", TLS 1.3) carries many streams;
// each stream is one tunnel connection, authenticated with an HMAC
// challenge so the token itself never crosses the wire in the clear:
// the server sends a random 32-byte challenge, the client answers with
// HMAC-SHA256(key=SHA256(token), challenge). A middlebox terminating
// the TLS holds a different session and cannot replay the proof.
package transport

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const hqALPN = "sopr-hq"

type hqFactory struct{}

func (f *hqFactory) Info() Info {
	return Info{
		Name:        "hq",
		Family:      "quic",
		Encrypted:   true,
		NeedsRoot:   false,
		SupportsUDP: true,
		Desc:        "QUIC (HTTP/3-style) multiplex: one TLS 1.3 QUIC connection, many streams, HMAC challenge auth (token never sent). Low latency, loss-resilient, NAT-friendly.",
	}
}

func hqTLSConfig(token string, server bool) (*tls.Config, error) {
	if server {
		cert, err := soprSelfSignedCert()
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{hqALPN},
		}, nil
	}
	return &tls.Config{
		InsecureSkipVerify: true, // trust is the token HMAC, not the cert
		NextProtos:         []string{hqALPN},
	}, nil
}

func hqClientAuth(st *quic.Stream, token string) error {
	// Server speaks first: 32-byte challenge.
	ch := make([]byte, 32)
	if _, err := io.ReadFull(st, ch); err != nil {
		return fmt.Errorf("hq: read challenge: %w", err)
	}
	key := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(ch)
	if _, err := st.Write(mac.Sum(nil)); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(st, ack); err != nil {
		return fmt.Errorf("hq: read auth ack: %w", err)
	}
	if ack[0] != 0x01 {
		return errors.New("hq: server rejected token")
	}
	return nil
}

func hqServerAuth(st *quic.Stream, token string) error {
	ch := make([]byte, 32)
	if _, err := rand.Read(ch); err != nil {
		return err
	}
	if _, err := st.Write(ch); err != nil {
		return err
	}
	got := make([]byte, 32)
	if _, err := io.ReadFull(st, got); err != nil {
		return fmt.Errorf("hq: read client proof: %w", err)
	}
	key := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(ch)
	if !hmac.Equal(got, mac.Sum(nil)) {
		_, _ = st.Write([]byte{0x00})
		return errors.New("hq: bad token proof")
	}
	_, err := st.Write([]byte{0x01})
	return err
}

// hqConn adapts a QUIC stream to net.Conn.
type hqConn struct {
	st     *quic.Stream
	qc     *quic.Conn
	tr     *quic.Transport // owned by Dial-created conns; nil on the server side
	local  net.Addr
	remote net.Addr
}

func (c *hqConn) Read(p []byte) (int, error)  { return c.st.Read(p) }
func (c *hqConn) Write(p []byte) (int, error) { return c.st.Write(p) }
func (c *hqConn) Close() error {
	_ = c.st.Close()
	if c.qc != nil {
		c.qc.CloseWithError(0, "closed")
	}
	if c.tr != nil {
		_ = c.tr.Close()
	}
	return nil
}
func (c *hqConn) LocalAddr() net.Addr  { return c.local }
func (c *hqConn) RemoteAddr() net.Addr { return c.remote }
func (c *hqConn) SetDeadline(t time.Time) error {
	if err := c.st.SetReadDeadline(t); err != nil {
		return err
	}
	return c.st.SetWriteDeadline(t)
}
func (c *hqConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *hqConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }

func (f *hqFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	tlsConf, err := hqTLSConfig(token, false)
	if err != nil {
		return nil, err
	}
	// Explicit IPv4 UDP socket: quic-go's default dual-stack socket
	// ([::]) is blocked on hosts without IPv6 UDP (sendmsg EPERM).
	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("hq: udp4 socket: %w", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("hq: resolve %s: %w", addr, err)
	}
	qc, err := tr.Dial(ctx, raddr, tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		tr.Close()
		return nil, fmt.Errorf("hq: dial quic: %w", err)
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		qc.CloseWithError(0, "open stream")
		tr.Close()
		return nil, err
	}
	if err := hqClientAuth(st, token); err != nil {
		st.Close()
		qc.CloseWithError(0, "auth")
		tr.Close()
		return nil, err
	}
	return &hqConn{st: st, qc: qc, tr: tr, local: qc.LocalAddr(), remote: qc.RemoteAddr()}, nil
}

type hqListener struct {
	ql       *quic.Listener
	tr       *quic.Transport
	udpConn  *net.UDPConn
	token    string
	acceptCh chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (f *hqFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	tlsConf, err := hqTLSConfig(token, true)
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("hq: resolve %s: %w", addr, err)
	}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("hq: listen udp4: %w", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	ql, err := tr.Listen(tlsConf, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("hq: listen quic: %w", err)
	}
	l := &hqListener{ql: ql, tr: tr, udpConn: udpConn, token: token, acceptCh: make(chan net.Conn, 64), done: make(chan struct{})}
	go l.serve(ctx)
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return l, nil
}

func (l *hqListener) serve(ctx context.Context) {
	for {
		qc, err := l.ql.Accept(ctx)
		if err != nil {
			return
		}
		go l.handleConn(ctx, qc)
	}
}

func (l *hqListener) handleConn(ctx context.Context, qc *quic.Conn) {
	for {
		st, err := qc.AcceptStream(ctx)
		if err != nil {
			return
		}
		if err := hqServerAuth(st, l.token); err != nil {
			st.Close()
			continue
		}
		select {
		case l.acceptCh <- &hqConn{st: st, qc: qc, local: qc.LocalAddr(), remote: qc.RemoteAddr()}:
		case <-l.done:
			st.Close()
			return
		}
	}
}

func (l *hqListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.done:
		return nil, errors.New("hq listener closed")
	}
}

func (l *hqListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.ql.Close()
		if l.tr != nil {
			_ = l.tr.Close()
		}
	})
	return err
}

func (l *hqListener) Addr() net.Addr { return l.ql.Addr() }
