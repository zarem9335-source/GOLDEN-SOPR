// Package web: GOLDEN SOPR web panel. Stdlib net/http only, embedded HTML
// (Persian RTL, dark). No dependency on core/metrics: the caller supplies
// tunnel data via Provider callbacks. Default listen 127.0.0.1:2097 —
// deliberately NOT 2096, which x-ui already holds on many servers.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack - AGPL-3.0.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soprpack/soprpack/internal/auth"
	"github.com/soprpack/soprpack/internal/config"
)

// TunnelStatus is what the dashboard shows per tunnel.
type TunnelStatus struct {
	Name      string  `json:"name"`
	Role      string  `json:"role"`
	Transport string  `json:"transport"`
	IranAddr  string  `json:"iran_addr"`
	Port      int     `json:"port"`
	Enabled   bool    `json:"enabled"`
	Up        bool    `json:"up"`
	BytesUp   int64   `json:"bytes_up"`
	BytesDown int64   `json:"bytes_down"`
	LatencyMs float64 `json:"latency_ms"`
}

// Provider supplies live data to the panel. All callbacks are optional.
type Provider struct {
	ListTunnels func() []config.Tunnel
	Status      func(name string) (TunnelStatus, bool)
	Metrics     func() map[string]any
	Health      func(name string) (bool, string)
	ApplyLink   func(link string) (*config.Tunnel, error)
	Save        func(cfg *config.Config) error
	Config      func() *config.Config
}

// Server is the web panel.
type Server struct {
	Addr     string
	Username string
	Password string
	Provider *Provider

	sessions *auth.SessionStore
	mu       sync.Mutex
}

func New(addr, username, password string, p *Provider) *Server {
	if addr == "" {
		addr = "127.0.0.1:2097"
	}
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = "admin123" // change on first login; see README
	}
	if p == nil {
		p = &Provider{}
	}
	return &Server{Addr: addr, Username: username, Password: password,
		Provider: p, sessions: auth.NewSessionStore(12 * time.Hour)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/tunnels", s.requireAuth(s.handleTunnels))
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/metrics", s.requireAuth(s.handleMetrics))
	mux.HandleFunc("/api/health", s.requireAuth(s.handleHealth))
	mux.HandleFunc("/api/events", s.requireAuth(s.handleEvents))
	return mux
}

// ListenAndServe runs the panel until ctx ends. If the configured port
// is already in use (e.g. another panel took 2097), it tries the next
// free port in 2097-2105 instead of failing, and updates s.Addr so the
// caller prints the port that actually works.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{Handler: s.Handler(),
		ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	host, portStr, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return srv.ListenAndServe()
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return srv.ListenAndServe()
	}
	var ln net.Listener
	for p := port; p <= port+8; p++ {
		ln, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			if p != port {
				fmt.Printf("GOLDEN SOPR: port %d is already in use, web panel moved to %d\n", port, p)
			}
			s.Addr = net.JoinHostPort(host, strconv.Itoa(p))
			break
		}
		if !strings.Contains(err.Error(), "address already in use") {
			return err
		}
	}
	if ln == nil {
		return err
	}
	fmt.Printf("GOLDEN SOPR web panel at http://%s (user: %s)\n", s.Addr, s.Username)
	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) authed(r *http.Request) bool {
	// Bearer session token first, then HTTP Basic Auth.
	if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" && tok != r.Header.Get("Authorization") {
		return s.sessions.Valid(tok)
	}
	u, p, ok := r.BasicAuth()
	return ok && auth.Check(u, p, s.Username, s.Password)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="GOLDEN SOPR"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if !auth.Check(in.Username, in.Password, s.Username, s.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"token": s.sessions.Issue()})
}

func (s *Server) tunnels() []TunnelStatus {
	p := s.Provider
	if p.ListTunnels == nil {
		return []TunnelStatus{}
	}
	out := []TunnelStatus{}
	for _, t := range p.ListTunnels() {
		st := TunnelStatus{Name: t.Name, Role: string(t.Role), Transport: t.Transport,
			IranAddr: t.IranAddr, Port: t.TunnelPort, Enabled: t.Enabled}
		if p.Status != nil {
			if full, ok := p.Status(t.Name); ok {
				st = full
			}
		}
		out = append(out, st)
	}
	return out
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.tunnels())
	case http.MethodPost:
		var t config.Tunnel
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := t.Validate(); err != nil {
			http.Error(w, "invalid tunnel: "+err.Error(), http.StatusBadRequest)
			return
		}
		if s.Provider.Config == nil || s.Provider.Save == nil {
			http.Error(w, "config provider not configured", http.StatusServiceUnavailable)
			return
		}
		cfg := s.Provider.Config()
		cfg.Upsert(t)
		if err := s.Provider.Save(cfg); err != nil {
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "tunnel": t})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"tunnels": s.tunnels(), "time": time.Now().Format(time.RFC3339)})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := map[string]any{}
	if s.Provider.Metrics != nil {
		m = s.Provider.Metrics()
	}
	if m == nil {
		m = map[string]any{}
	}
	m["tunnels"] = s.tunnels()
	writeJSON(w, m)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if s.Provider.Health == nil {
		writeJSON(w, map[string]any{"ok": true, "note": "health provider not configured"})
		return
	}
	ok, msg := s.Provider.Health(name)
	writeJSON(w, map[string]any{"ok": ok, "name": name, "message": msg})
}

// handleEvents streams metrics as SSE every 2s.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			m := map[string]any{"tunnels": s.tunnels(), "time": time.Now().Format(time.RFC3339)}
			if s.Provider.Metrics != nil {
				if extra := s.Provider.Metrics(); extra != nil {
					for k, v := range extra {
						m[k] = v
					}
				}
			}
			b, _ := json.Marshal(m)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

const indexHTML = `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GOLDEN SOPR — پنل تونل</title>
<style>body{background:#0b1220;color:#e5e7eb;font-family:Tahoma,sans-serif;margin:0;padding:24px}
h1{color:#FFD700}table{width:100%;border-collapse:collapse;background:#111827;border-radius:8px;overflow:hidden}
th,td{padding:10px;border-bottom:1px solid #1f2937;text-align:right}th{color:#9ca3af}
.badge{padding:2px 8px;border-radius:999px;background:#065f46}.down{background:#7f1d1d}
a{color:#FFD700}.gold{color:#FFD700}button{background:#F5C518;color:#111;border:none;font-weight:bold;cursor:pointer}input,button{padding:8px;border-radius:6px;border:1px solid #374151;background:#1f2937;color:#fff}
</style></head><body>
<h1>✨ GOLDEN SOPR — پنل مدیریت تونل</h1>
<p>وضعیت زندهٔ تونل‌ها — برای API از Basic Auth (admin) استفاده کنید.</p>
<p><a href="/api/status">/api/status</a> · <a href="/api/tunnels">/api/tunnels</a> · <a href="/api/metrics">/api/metrics</a> · <a href="/api/events">/api/events (SSE)</a></p>
<table id="t"><thead><tr><th>نام</th><th>نقش</th><th>ترنسپورت</th><th>آدرس ایران</th><th>پورت</th><th>وضعیت</th></tr></thead><tbody></tbody></table>
<pre id="log"></pre>
<script>
async function load(){try{const r=await fetch('/api/status');const j=await r.json();
document.querySelector('#t tbody').innerHTML=(j.tunnels||[]).map(t=>'<tr><td>'+t.name+'</td><td>'+t.role+'</td><td>'+t.transport+'</td><td>'+t.iran_addr+'</td><td>'+t.port+'</td><td><span class="badge '+(t.up?'':'down')+'">'+(t.up?'UP':'DOWN')+'</span></td></tr>').join('')||'<tr><td colspan=6>تونلی ساخته نشده — از CLI با sopr setup-iran شروع کنید.</td></tr>';
}catch(e){document.getElementById('log').textContent='خطا در خواندن وضعیت: '+e+' (وارد شوید)'}}
load();setInterval(load,5000);
const es=new EventSource('/api/events');es.onmessage=e=>{document.getElementById('log').textContent='آخرین به‌روزرسانی: '+new Date().toLocaleTimeString('fa-IR');};
</script></body></html>`
