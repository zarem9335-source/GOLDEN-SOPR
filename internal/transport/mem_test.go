package transport

import (
	"encoding/base64"
	"net"
	"sync"
	"testing"
	"time"
)

// memIO is an in-memory packetIO: one Read returns one datagram.
// Used to verify the Noise handshake + AEAD session without real UDP,
// because this sandbox blocks UDP replies (server->client sendto EPERM).
type memIO struct {
	in       chan []byte
	peer     *memIO
	local    net.Addr
	remote   net.Addr
	mu       sync.Mutex
	closed   bool
	deadline time.Time
}

func memPipe() (*memIO, *memIO) {
	a := &memIO{in: make(chan []byte, 64), local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}, remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10002}}
	b := &memIO{in: make(chan []byte, 64), local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10002}, remote: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}}
	a.peer, b.peer = b, a
	return a, b
}

func (m *memIO) Read(p []byte) (int, error) {
	m.mu.Lock()
	dl := m.deadline
	m.mu.Unlock()
	if !dl.IsZero() {
		timer := time.NewTimer(time.Until(dl))
		defer timer.Stop()
		select {
		case d, ok := <-m.in:
			if !ok {
				return 0, errClosed
			}
			return copy(p, d), nil
		case <-timer.C:
			return 0, errTimeout
		}
	}
	d, ok := <-m.in
	if !ok {
		return 0, errClosed
	}
	return copy(p, d), nil
}

func (m *memIO) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case m.peer.in <- cp:
		return len(p), nil
	default:
		// Buffer full: still deliver (blocking send with a short cap).
		m.peer.in <- cp
		return len(p), nil
	}
}

func (m *memIO) Close() error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.in)
	}
	m.mu.Unlock()
	return nil
}

func (m *memIO) LocalAddr() net.Addr  { return m.local }
func (m *memIO) RemoteAddr() net.Addr { return m.remote }
func (m *memIO) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.deadline = t
	m.mu.Unlock()
	return nil
}
func (m *memIO) SetWriteDeadline(t time.Time) error { return nil }
func (m *memIO) SetTOS(tos int) error               { return nil }

var errClosed = &memErr{"closed"}
var errTimeout = &memErr{"timeout"}

type memErr struct{ s string }

func (e *memErr) Error() string { return e.s }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestMemWGHandshakeEcho(t *testing.T) {
	privA, pubA, err := wgStaticKey("token-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, err := wgStaticKey("token-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := memPipe()
	// Responder side.
	hsBCh := make(chan *wgHandshake, 1)
	go func() {
		tmp := make([]byte, 4096)
		n, err := b.Read(tmp)
		if err != nil {
			t.Errorf("responder read init: %v", err)
			return
		}
		hs, _, resp, err := wgHandshakeResponder(tmp[:n], privB, pubB)
		if err != nil {
			t.Errorf("responder handshake: %v", err)
			return
		}
		if _, err := b.Write(resp); err != nil {
			t.Errorf("responder write: %v", err)
			return
		}
		hsBCh <- hs
	}()
	hsA, err := wgHandshakeInitiator(a, pubB, privA, pubA, 5*time.Second)
	if err != nil {
		t.Fatalf("initiator handshake: %v", err)
	}
	hsB := <-hsBCh
	ca := newWGConn(a, hsA, a.LocalAddr(), a.RemoteAddr())
	cb := newWGConn(b, hsB, b.LocalAddr(), b.RemoteAddr())
	defer ca.Close()
	defer cb.Close()
	// Echo over the AEAD session.
	go func() {
		buf := make([]byte, 1024)
		n, err := cb.Read(buf)
		if err != nil {
			return
		}
		_, _ = cb.Write(buf[:n])
	}()
	msg := []byte("wg-mem-echo")
	if _, err := ca.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1024)
	_ = ca.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ca.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo mismatch: %q", buf[:n])
	}
	// Wrong token must fail the handshake: the initiator encrypts its
	// static key under a responder public key derived from a different
	// token, so the responder cannot decrypt it and stays silent.
	_, wrongPub, _ := wgStaticKey("token-wrong", nil)
	a2, b2 := memPipe()
	go func() {
		tmp := make([]byte, 4096)
		n, _ := b2.Read(tmp)
		_, _, _, err := wgHandshakeResponder(tmp[:n], privB, pubB)
		if err == nil {
			t.Errorf("responder accepted a handshake encrypted to a wrong key")
		}
	}()
	if _, err := wgHandshakeInitiator(a2, wrongPub, privA, pubA, time.Second); err == nil {
		t.Fatalf("initiator handshake with wrong peer key should fail")
	}
}

func TestMemWGGamingEcho(t *testing.T) {
	privA, pubA, _ := wgStaticKey("game-a", nil)
	privB, pubB, _ := wgStaticKey("game-b", nil)
	extraA := map[string]string{"wg_public_key": b64(pubB)}
	extraB := map[string]string{"wg_public_key": b64(pubA)}
	_ = extraA
	_ = extraB
	// Two subflow pairs.
	var subsA, subsB []*wgPacketConn
	for i := 0; i < 2; i++ {
		a, b := memPipe()
		hsBCh := make(chan *wgHandshake, 1)
		go func(b *memIO) {
			tmp := make([]byte, 4096)
			n, err := b.Read(tmp)
			if err != nil {
				return
			}
			hs, _, resp, err := wgHandshakeResponder(tmp[:n], privB, pubB)
			if err != nil {
				return
			}
			_, _ = b.Write(resp)
			hsBCh <- hs
		}(b)
		hsA, err := wgHandshakeInitiator(a, pubB, privA, pubA, 5*time.Second)
		if err != nil {
			t.Fatalf("subflow %d initiator: %v", i, err)
		}
		hsB := <-hsBCh
		subsA = append(subsA, newWGConn(a, hsA, a.LocalAddr(), a.RemoteAddr()))
		subsB = append(subsB, newWGConn(b, hsB, b.LocalAddr(), b.RemoteAddr()))
	}
	tuning := DefaultGamingTuning()
	game := NewGamePortSet(nil)
	ga := newGamingConn(subsA, tuning, game, subsA[0].LocalAddr())
	gb := newGamingConn(subsB, tuning, game, subsB[0].LocalAddr())
	defer ga.Close()
	defer gb.Close()
	if !ga.IsGamePort(27015) || ga.IsGamePort(443) {
		t.Fatalf("game port classification broken on gaming conn")
	}
	if ga.MTU() != 1280 || ga.MSSClamp() != 1240 {
		t.Fatalf("MTU/MSS wrong: %d/%d", ga.MTU(), ga.MSSClamp())
	}
	// Echo: gb reads one message and writes it back.
	go func() {
		buf := make([]byte, 4096)
		n, err := gb.Read(buf)
		if err != nil || n == 0 {
			t.Errorf("gb read: n=%d err=%v", n, err)
			return
		}
		_, _ = gb.Write(buf[:n])
	}()
	msg := []byte("gaming-echo-27015")
	if _, err := ga.Write(msg); err != nil {
		t.Fatalf("ga write: %v", err)
	}
	buf := make([]byte, 4096)
	_ = ga.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ga.Read(buf)
	if err != nil {
		t.Fatalf("ga read echo: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("gaming echo mismatch: got %q want %q", buf[:n], msg)
	}
	// Stats are being collected.
	st := ga.Stats()
	if st.Sent == 0 {
		t.Fatalf("gaming stats show no sent frames: sent=%d recv=%d", st.Sent, st.Recv)
	}
}
