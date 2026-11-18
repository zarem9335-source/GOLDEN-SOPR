// GOLDEN SOPR — "grpc" transport: bidirectional stream over HTTP/2.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// One HTTP/2 POST to /sopr.Tunnel/Stream is one tunnel connection: the
// request body is the upstream stream, the response body the downstream
// stream. HTTP/2 multiplexing gives many streams over one TCP/TLS
// connection with header compression and flow control, and the traffic
// looks like ordinary gRPC/HTTP-2 API traffic to a middlebox. Token is
// carried in the X-Sopr-Token header and checked before any body flows.
// Plain h2c by default; set extra tls=1 (with cert/key) for HTTPS.
package transport

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const grpcPath = "/sopr.Tunnel/Stream"

// grpcConn is one HTTP/2 stream exposed as a net.Conn.
type grpcConn struct {
	r       io.ReadCloser // request body (client) / response body (server side read)
	w       io.Writer     // pipe writer (client) / response writer (server)
	flush   func()
	local   net.Addr
	remote  net.Addr
	closeMu sync.Mutex
	closed  bool
	onClose func()
}

func (c *grpcConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *grpcConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *grpcConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	c.closeMu.Unlock()
	if c.onClose != nil {
		c.onClose()
	}
	return c.r.Close()
}

func (c *grpcConn) LocalAddr() net.Addr                { return c.local }
func (c *grpcConn) RemoteAddr() net.Addr               { return c.remote }
func (c *grpcConn) SetDeadline(t time.Time) error      { return nil }
func (c *grpcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { return nil }

type grpcFactory struct{}

func (f *grpcFactory) Info() Info {
	return Info{
		Name:        "grpc",
		Family:      "grpc",
		Encrypted:   false,
		NeedsRoot:   false,
		SupportsUDP: true,
		Desc:        "Bidirectional stream over HTTP/2 (gRPC-style): one POST per tunnel connection, multiplexed, header-compressed. Token in header. Set tls=1 with cert/key for HTTPS.",
	}
}

func (f *grpcFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+grpcPath, pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Sopr-Token", token)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("grpc: roundtrip: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("grpc: server status %s", resp.Status)
	}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
	remote, _ := net.ResolveTCPAddr("tcp", addr)
	return &grpcConn{
		r: resp.Body, w: pw, local: local, remote: remote,
		onClose: func() { pw.Close(); resp.Body.Close() },
	}, nil
}

// grpcListener serves h2c and turns each POST into a net.Conn.
type grpcListener struct {
	ln       net.Listener
	srv      *http.Server
	token    string
	acceptCh chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (f *grpcFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("grpc: listen: %w", err)
	}
	l := &grpcListener{
		ln: ln, token: token,
		acceptCh: make(chan net.Conn, 64),
		done:     make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(grpcPath, l.handleStream)
	l.srv = &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	go func() { _ = l.srv.Serve(ln) }()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return l, nil
}

func (l *grpcListener) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Sopr-Token")), []byte(l.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	// Downstream: handler writes response body from this pipe.
	pr, pw := io.Pipe()
	done := make(chan struct{})
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			close(done)
			pw.Close()
			_ = r.Body.Close()
		})
	}
	c := &grpcConn{
		r: r.Body, w: pw, local: l.ln.Addr(), remote: parseRemoteAddr(r.RemoteAddr),
		flush:   fl.Flush,
		onClose: closeAll,
	}
	select {
	case l.acceptCh <- c:
	case <-l.done:
		closeAll()
		return
	}
	// Pump downstream pipe -> response until the connection closes.
	_, _ = io.Copy(w, pr)
	closeAll()
}

func parseRemoteAddr(s string) net.Addr {
	if a, err := net.ResolveTCPAddr("tcp", s); err == nil {
		return a
	}
	return &net.TCPAddr{}
}

func (l *grpcListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.done:
		return nil, errors.New("grpc listener closed")
	}
}

func (l *grpcListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.srv.Close()
	})
	return err
}

func (l *grpcListener) Addr() net.Addr { return l.ln.Addr() }
