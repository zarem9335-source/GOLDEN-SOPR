package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soprpack/soprpack/internal/config"
)

func TestPanelAuthAndAPI(t *testing.T) {
	p := &Provider{ListTunnels: func() []config.Tunnel {
		return []config.Tunnel{{Name: "main", Role: "iran", Transport: "wg-gaming", IranAddr: "1.2.3.4", TunnelPort: 4433, Enabled: true}}
	}}
	srv := New("127.0.0.1:2097", "admin", "admin123", p)
	h := srv.Handler()

	// No auth -> 401.
	req := httptest.NewRequest(http.MethodGet, "/api/tunnels", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/tunnels = %d, want 401", rec.Code)
	}
	// Basic auth -> 200 and contains the tunnel + gold title on index.
	req = httptest.NewRequest(http.MethodGet, "/api/tunnels", nil)
	req.SetBasicAuth("admin", "admin123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "wg-gaming") {
		t.Fatalf("authenticated /api/tunnels = %d body %q", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password index = %d, want 401", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "admin123")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "GOLDEN SOPR") || !strings.Contains(rec.Body.String(), "#FFD700") {
		t.Fatalf("index = %d, missing GOLDEN SOPR gold theme", rec.Code)
	}
}
