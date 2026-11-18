package transport

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateCerts(t *testing.T) {
	if err := ValidateCerts("", ""); err != nil {
		t.Fatalf("empty cert/key must be OK (self-signed/REALITY): %v", err)
	}
	if err := ValidateCerts("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Fatal("missing cert files must fail validation")
	}
	if err := ValidateCerts("/tmp/x.pem", ""); err == nil {
		t.Fatal("cert without key must fail validation")
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(cert, []byte("x"), 0o600)
	_ = os.WriteFile(key, []byte("x"), 0o600)
	if err := ValidateCerts(cert, key); err != nil {
		t.Fatalf("existing cert/key must validate: %v", err)
	}
}

func TestHelperStartStop(t *testing.T) {
	h := &Helper{Binary: "/nonexistent/sing-box"}
	if err := h.Start(); err == nil {
		t.Fatal("missing helper binary must fail Start")
	}
	h2 := &Helper{Binary: "/bin/sleep", Args: []string{"30"}}
	if _, err := h2.WriteConfig(HelperConfig{Mode: "naive", Listen: "0.0.0.0:443"}); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	// Config must be owner-only.
	st, err := os.Stat(filepath.Join(h2.Dir, "helper.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("helper config perms: %v %v", st, err)
	}
	if err := h2.Start(); err != nil {
		t.Fatalf("Start sleep helper: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if !h2.Running() {
		t.Fatal("helper should be running")
	}
	if err := h2.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if h2.Running() {
		t.Fatal("helper should be stopped")
	}
	if _, err := os.Stat(h2.Dir); !os.IsNotExist(err) {
		t.Fatalf("helper temp dir should be removed after Stop")
	}
}
