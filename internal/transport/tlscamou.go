// GOLDEN SOPR — "tls-camou" transport: TLS with a Chrome fingerprint.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// The client speaks TLS with uTLS HelloChrome_Auto, so the ClientHello
// is byte-identical to Chrome's (cipher suites, extensions, order,
// GREASE). SNI comes from Extra["sni"] (default: the dial host) and
// ALPN offers h2 + http/1.1. The server answers with a real TLS stack
// (self-signed cert unless cert/key are given). After the handshake the
// token is checked in-band, so a plain TLS-terminating middlebox cannot
// complete the tunnel. Certificate verification is off on the client:
// trust is the token, not a CA — the same model as BackPack's QUIC.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	tlsutls "github.com/refraction-networking/utls"
)

type tlsCamouFactory struct{}

func (f *tlsCamouFactory) Info() Info {
	return Info{
		Name:        "tls-camou",
		Family:      "tcp",
		Encrypted:   true,
		NeedsRoot:   false,
		SupportsUDP: true,
		NeedsCert:   false,
		Desc:        "TLS camouflage: uTLS Chrome ClientHello fingerprint, configurable SNI, ALPN h2/http1.1, token auth after handshake. Looks like ordinary Chrome HTTPS.",
	}
}

// soprSelfSignedCert mints an ECDSA P-256 cert for "sopr.local" (10y).
// Shared by tls-camou and hq; replace with a real cert via Extra cert/key.
func soprSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sopr.local", Organization: []string{"GOLDEN SOPR"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"sopr.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

func camouServerTLS(extra map[string]string) (*tls.Config, error) {
	if certFile := strings.TrimSpace(extra["cert"]); certFile != "" {
		keyFile := strings.TrimSpace(extra["key"])
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tls-camou: load cert: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
	}
	cert, err := soprSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
}

func camouSNI(addr string, extra map[string]string) string {
	if s := strings.TrimSpace(extra["sni"]); s != "" {
		return s
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// writeToken / readToken: [len 2][token] then 1-byte 0x01 ack.
func camouWriteToken(c net.Conn, token string) error {
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(token)))
	if _, err := c.Write(append(lb[:], token...)); err != nil {
		return err
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(c, ack); err != nil {
		return err
	}
	if ack[0] != 0x01 {
		return errors.New("tls-camou: server rejected token")
	}
	return nil
}

func camouReadToken(c net.Conn, token string) error {
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n <= 0 || n > 4096 {
		return errors.New("tls-camou: bad token length")
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, []byte(token)) != 1 {
		_, _ = c.Write([]byte{0x00})
		return errors.New("tls-camou: bad token")
	}
	_, err := c.Write([]byte{0x01})
	return err
}

func (f *tlsCamouFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tlsutls.Config{
		ServerName:         camouSNI(addr, extra),
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	u := tlsutls.UClient(raw, cfg, tlsutls.HelloChrome_Auto)
	if err := u.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls-camou: handshake: %w", err)
	}
	if err := camouWriteToken(u, token); err != nil {
		u.Close()
		return nil, err
	}
	return u, nil
}

type tlsCamouListener struct {
	ln    net.Listener
	cfg   *tls.Config
	token string
	once  sync.Once
}

func (f *tlsCamouFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	cfg, err := camouServerTLS(extra)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &tlsCamouListener{ln: tls.NewListener(ln, cfg), token: token}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return l, nil
}

func (l *tlsCamouListener) Accept() (net.Conn, error) {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return nil, err
		}
		if err := camouReadToken(c, l.token); err != nil {
			c.Close()
			continue // unauthenticated: drop, keep listening
		}
		return c, nil
	}
}

func (l *tlsCamouListener) Close() error {
	var err error
	l.once.Do(func() { err = l.ln.Close() })
	return err
}

func (l *tlsCamouListener) Addr() net.Addr { return l.ln.Addr() }
