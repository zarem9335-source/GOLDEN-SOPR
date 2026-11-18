package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/soprpack/soprpack/internal/config"
	"github.com/soprpack/soprpack/internal/fec"
	"github.com/soprpack/soprpack/internal/metrics"
)

// echoBackend is a tiny TCP echo server on 127.0.0.1:port.
func echoBackend(t *testing.T, port int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

func runPair(t *testing.T, transport string, tunnelPort, fwdPort, backPort int) {
	t.Helper()
	backend := echoBackend(t, backPort)
	defer backend.Close()

	iranTun := config.Tunnel{Name: "smoke-" + transport, Role: config.RoleIran,
		Transport: transport, IranAddr: "127.0.0.1", TunnelPort: tunnelPort,
		Ports: []string{fmt.Sprintf("%d=127.0.0.1:%d", fwdPort, backPort)},
		Token: "golden-sopr-smoke-token", Preset: config.PresetBalanced, Enabled: true}
	kharejTun := iranTun
	kharejTun.Role = config.RoleKharej
	if transport == "wss" {
		// Server uses a self-signed cert in the smoke test.
		kharejTun.Extra = map[string]string{"insecure": "true"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	iran := New(iranTun)
	kharej := New(kharejTun)
	go func() { _ = iran.RunServer(ctx) }()
	go func() { _ = kharej.RunClient(ctx) }()

	// Dial the Iran forwarded port; traffic must come back from the backend
	// on Kharej via the tunnel.
	var conn net.Conn
	var err error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("%s: dial forwarded port: %v", transport, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("hello-golden-sopr")); err != nil {
		t.Fatalf("%s: write: %v", transport, err)
	}
	r := bufio.NewReader(conn)
	got, err := r.ReadString('r') // "hello-golden-sopr" ends in 'r'
	if err != nil {
		t.Fatalf("%s: read echo: %v", transport, err)
	}
	if got != "hello-golden-sopr" {
		t.Fatalf("%s: echo mismatch: %q", transport, got)
	}
	if kharej.Metrics.Snapshot()["tunnels"] == nil {
		t.Fatalf("%s: metrics snapshot empty", transport)
	}
	cancel()
	kharej.Stop()
	iran.Stop()
}

func TestSmokeTCP(t *testing.T)     { runPair(t, "tcp", 19001, 18080, 18081) }
func TestSmokeWS(t *testing.T)      { runPair(t, "ws", 19002, 18082, 18083) }
func TestSmokeStealth(t *testing.T) { runPair(t, "tcp-stealth", 19003, 18084, 18085) }
func TestSmokePCK(t *testing.T)     { runPair(t, "tcp-pck", 19004, 18086, 18087) }

// udpAvailable probes whether this machine can send UDP at all; sandboxes
// (and this CI VM) block UDP sends with EPERM, so UDP transports are
// skipped there instead of failing. On a real VPS they run.
func udpAvailable() bool {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer pc.Close()
	ua, err := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	if err != nil {
		return false
	}
	_, err = pc.WriteTo([]byte("probe"), ua)
	return err == nil
}

func TestSmokeKCP(t *testing.T) {
	if !udpAvailable() {
		t.Skip("UDP sends blocked in this environment (EPERM); test on a VPS")
	}
	runPair(t, "udp-kcp", 19005, 18088, 18089)
}
func TestSmokeQUIC(t *testing.T) {
	if !udpAvailable() {
		t.Skip("UDP sends blocked in this environment (EPERM); test on a VPS")
	}
	runPair(t, "udp-quic", 19006, 18090, 18091)
}
func TestSmokeWSS(t *testing.T) { runPair(t, "wss", 19007, 18092, 18093) }

func TestFECRoundTrip(t *testing.T) {
	data := []byte("golden-sopr fec round trip payload 1234567890")
	shards, ln, err := fec.EncodeDefault(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Lose two shards (parity count) and reconstruct.
	shards[1] = nil
	shards[8] = nil
	out, err := fec.DecodeDefault(shards, ln)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(out) != string(data) {
		t.Fatalf("fec mismatch: %q", out)
	}
}

func TestMetricsStore(t *testing.T) {
	m := metrics.New()
	m.AddBytes("t1", 100)
	m.AddUp("t1", 50)
	m.AddDown("t1", 25)
	m.AddConn("t1")
	snap := m.Snapshot()
	if snap["tunnels"] == nil {
		t.Fatalf("no tunnels in snapshot")
	}
}
