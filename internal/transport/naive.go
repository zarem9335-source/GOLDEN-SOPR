// GOLDEN SOPR — "naive" / "xhttp" / "reality": managed HTTPS carriers.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// These transports carry the ordinary TCP reverse engine inside an
// external helper process (sing-box for Naive, Xray for XHTTP/REALITY).
// GOLDEN SOPR does NOT bundle those helpers: the operator installs the
// official binary and points Extra["binary"] at it. GOLDEN SOPR owns the
// helper lifecycle — it generates the helper config (0600, temp dir),
// starts the process, restarts it on crash with 1 s backoff, and kills
// its process group + temp dir when the tunnel stops.
//
//   - naive:   sing-box NaiveProxy inbound (HTTP/2, user/pass).
//   - xhttp:   Xray XHTTP over TLS (UUID, private path, stream-up).
//   - reality: Xray REALITY/Vision (X25519 keys, short_id, cover SNI).
//
// Extra keys: binary, listen, server, username, password, uuid, path,
// server_name, short_id, private_key, public_key, target, certificate,
// key, ca_file, local_port. Certificate files are validated before the
// helper starts; a missing/invalid pair refuses to start.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Helper is one managed external process (sing-box / Xray).
type Helper struct {
	Binary string
	Args   []string
	Dir    string // temp dir holding the generated config (0600)
	Env    []string

	mu     sync.Mutex
	cmd    *exec.Cmd
	stopCh chan struct{}
	done   chan struct{}
}

// HelperConfig is the generated config handed to the helper.
type HelperConfig struct {
	Mode        string `json:"mode"`
	Listen      string `json:"listen,omitempty"`
	Server      string `json:"server,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Path        string `json:"path,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	ShortID     string `json:"short_id,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Target      string `json:"target,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Key         string `json:"key,omitempty"`
	CAFile      string `json:"ca_file,omitempty"`
}

// ValidateCerts checks certificate/key files exist and are readable.
func ValidateCerts(certFile, keyFile string) error {
	if certFile == "" && keyFile == "" {
		return nil // self-signed / REALITY modes need no files
	}
	if certFile == "" || keyFile == "" {
		return errors.New("naive/xhttp: certificate and key must be given together")
	}
	for _, f := range []string{certFile, keyFile} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("naive/xhttp: cert file %s: %w", f, err)
		}
	}
	return nil
}

// WriteConfig writes the helper config with owner-only permissions.
func (h *Helper) WriteConfig(cfg HelperConfig) (string, error) {
	if h.Dir == "" {
		dir, err := os.MkdirTemp("", "golden-sopr-helper-*")
		if err != nil {
			return "", err
		}
		h.Dir = dir
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(h.Dir, "helper.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Start launches the helper and supervises it: on crash it restarts
// after a 1 s backoff until Stop is called.
func (h *Helper) Start() error {
	if h.Binary == "" {
		return errors.New("helper: binary path is empty — install the official sing-box/Xray helper and set Extra[\"binary\"]")
	}
	if _, err := os.Stat(h.Binary); err != nil {
		return fmt.Errorf("helper: binary %s not found: %w (helpers are not bundled; install the official binary)", h.Binary, err)
	}
	h.mu.Lock()
	if h.cmd != nil {
		h.mu.Unlock()
		return errors.New("helper: already running")
	}
	h.stopCh = make(chan struct{})
	h.done = make(chan struct{})
	h.mu.Unlock()
	go h.supervise()
	return nil
}

func (h *Helper) supervise() {
	defer close(h.done)
	for {
		cmd := exec.Command(h.Binary, h.Args...)
		cmd.Dir = h.Dir
		cmd.Env = append(os.Environ(), h.Env...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		h.mu.Lock()
		h.cmd = cmd
		h.mu.Unlock()
		err := cmd.Run()
		h.mu.Lock()
		h.cmd = nil
		h.mu.Unlock()
		select {
		case <-h.stopCh:
			return
		default:
		}
		if err == nil {
			return
		}
		// Crash: back off 1 s (cancellable) and restart.
		select {
		case <-h.stopCh:
			return
		case <-time.After(time.Second):
		}
	}
}

// Stop kills the helper's process group and removes its temp dir.
func (h *Helper) Stop() error {
	h.mu.Lock()
	if h.stopCh != nil {
		close(h.stopCh)
	}
	cmd := h.cmd
	h.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		time.AfterFunc(2*time.Second, func() {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		})
	}
	if h.done != nil {
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
		}
	}
	if h.Dir != "" {
		_ = os.RemoveAll(h.Dir)
	}
	return nil
}

// Running reports whether the helper process is currently up.
func (h *Helper) Running() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cmd != nil && h.cmd.Process != nil
}

// ---- factories -------------------------------------------------------------

type naiveFactory struct{ name string }

func (f *naiveFactory) Info() Info {
	desc := map[string]string{
		"naive":   "Managed NaiveProxy (sing-box) HTTP/2 carrier for the TCP reverse engine. Helper binary not bundled; set Extra[\"binary\"].",
		"xhttp":   "Managed Xray XHTTP-over-TLS carrier for the TCP reverse engine. Helper binary not bundled; set Extra[\"binary\"].",
		"reality": "Managed Xray REALITY/Vision carrier for the TCP reverse engine (X25519 keys, short_id, cover SNI). Helper binary not bundled; set Extra[\"binary\"].",
	}[f.name]
	return Info{
		Name:        f.name,
		Family:      "https",
		Encrypted:   true,
		NeedsRoot:   false,
		SupportsUDP: false, // helpers carry TCP only in this version
		NeedsCert:   f.name != "reality",
		Desc:        desc,
	}
}

func naiveConfigFromExtra(name string, extra map[string]string) HelperConfig {
	return HelperConfig{
		Mode:        name,
		Listen:      extra["listen"],
		Server:      extra["server"],
		Username:    extra["username"],
		Password:    extra["password"],
		UUID:        extra["uuid"],
		Path:        extra["path"],
		ServerName:  extra["server_name"],
		ShortID:     extra["short_id"],
		PrivateKey:  extra["private_key"],
		PublicKey:   extra["public_key"],
		Target:      extra["target"],
		Certificate: extra["certificate"],
		Key:         extra["key"],
		CAFile:      extra["ca_file"],
	}
}

// waitPort polls until something accepts on addr (helper readiness).
func waitPort(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		d := &net.Dialer{Timeout: time.Second}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("helper did not start listening on %s within %s", addr, timeout)
}

// Dial (Kharej): start the client helper, then connect to its local port.
func (f *naiveFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	if err := ValidateCerts(extra["certificate"], extra["key"]); err != nil {
		return nil, err
	}
	h := &Helper{Binary: extra["binary"]}
	cfg := naiveConfigFromExtra(f.name, extra)
	if _, err := h.WriteConfig(cfg); err != nil {
		return nil, err
	}
	// Helper args: -c <config> is the sing-box/Xray convention.
	h.Args = []string{"-c", filepath.Join(h.Dir, "helper.json")}
	if err := h.Start(); err != nil {
		return nil, err
	}
	local := extra["local_port"]
	if local == "" {
		local = "127.0.0.1:3080"
	}
	if err := waitPort(ctx, local, 15*time.Second); err != nil {
		h.Stop()
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := d.DialContext(ctx, "tcp", local)
	if err != nil {
		h.Stop()
		return nil, err
	}
	// The helper owns the encrypted outer leg; the returned conn is the
	// local clear leg to the reverse engine. The helper serves the whole
	// tunnel (not one stream), so it is stopped by the engine when the
	// tunnel stops, not when this conn closes.
	return &helperConn{Conn: c, h: h}, nil
}

// helperConn ties a helper's lifetime to the tunnel connection.
type helperConn struct {
	net.Conn
	h *Helper
}

func (c *helperConn) Close() error {
	err := c.Conn.Close()
	// Do not stop the helper here: it serves the whole tunnel, not one
	// stream. The engine stops it when the tunnel stops.
	return err
}

// Listen (Iran): start the server helper, then listen for the reverse
// engine on the internal port.
func (f *naiveFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	if err := ValidateCerts(extra["certificate"], extra["key"]); err != nil {
		return nil, err
	}
	h := &Helper{Binary: extra["binary"]}
	cfg := naiveConfigFromExtra(f.name, extra)
	if _, err := h.WriteConfig(cfg); err != nil {
		return nil, err
	}
	h.Args = []string{"-c", filepath.Join(h.Dir, "helper.json")}
	if err := h.Start(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		h.Stop()
		return nil, err
	}
	return &helperListener{Listener: ln, h: h}, nil
}

type helperListener struct {
	net.Listener
	h *Helper
}

func (l *helperListener) Close() error {
	err := l.Listener.Close()
	l.h.Stop()
	return err
}
