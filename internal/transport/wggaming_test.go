// GOLDEN SOPR — tests for the wg-gaming transport.
package transport

import (
	"testing"
	"time"
)

func TestIsGamePort(t *testing.T) {
	s := NewGamePortSet(nil) // defaults
	for _, p := range []int{27015, 3074, 3478, 7777, 25565} {
		if !s.IsGamePort(p) {
			t.Errorf("expected port %d to be a game port", p)
		}
		if s.Classify(p) != "game" {
			t.Errorf("expected port %d to classify as game", p)
		}
	}
	for _, p := range []int{80, 443, 22, 8080} {
		if s.IsGamePort(p) {
			t.Errorf("expected port %d NOT to be a game port", p)
		}
		if s.Classify(p) != "bulk" {
			t.Errorf("expected port %d to classify as bulk", p)
		}
	}
	// Custom list + ranges.
	s2 := NewGamePortSet(ParseGamePorts("27015, 30000-30002"))
	if !s2.IsGamePort(30001) || s2.IsGamePort(3074) {
		t.Errorf("custom game port set wrong: 30001=%v 3074=%v", s2.IsGamePort(30001), s2.IsGamePort(3074))
	}
}

func TestDSCPConstant(t *testing.T) {
	if DSCPEF != 184 {
		t.Fatalf("DSCP EF must be 184 (0xb8), got %d", DSCPEF)
	}
	if DSCPEF>>2 != 46 {
		t.Fatalf("DSCP EF must be DSCP 46, got %d", DSCPEF>>2)
	}
}

func TestGamingTuning(t *testing.T) {
	gt := DefaultGamingTuning()
	if gt.MTU != 1280 {
		t.Errorf("MTU = %d, want 1280", gt.MTU)
	}
	if gt.MSS != 1240 {
		t.Errorf("MSS = %d, want 1240", gt.MSS)
	}
	if gt.KeepaliveSec != 5 {
		t.Errorf("KeepaliveSec = %d, want 5", gt.KeepaliveSec)
	}
	if gt.HandshakeRetry != 500*time.Millisecond {
		t.Errorf("HandshakeRetry = %v, want 500ms", gt.HandshakeRetry)
	}
	if !gt.DupEnabled {
		t.Errorf("DupEnabled must default to true")
	}
	if gt.FECShards != 4 {
		t.Errorf("FECShards = %d, want 4", gt.FECShards)
	}
	if gt.DSCP != DSCPEF {
		t.Errorf("DSCP = %d, want %d", gt.DSCP, DSCPEF)
	}
	if gt.RTTSwitchMs != 120 || gt.LossSwitchPct != 3.0 {
		t.Errorf("switch thresholds = %v/%v, want 120ms/3%%", gt.RTTSwitchMs, gt.LossSwitchPct)
	}
	// Extra overrides.
	gt2 := TuningFromExtra(map[string]string{"mtu": "1400", "duplicate_udp": "false", "fec": "false"})
	if gt2.MTU != 1400 || gt2.MSS != 1360 || gt2.DupEnabled || gt2.FECShards != 0 {
		t.Errorf("TuningFromExtra wrong: %+v", gt2)
	}
}

func TestDedupReceiver(t *testing.T) {
	d := newDedupReceiver()
	if d.Seen(42) {
		t.Fatal("first sighting of seq 42 must not be a duplicate")
	}
	if !d.Seen(42) {
		t.Fatal("second sighting of seq 42 must be a duplicate")
	}
	if d.Seen(43) {
		t.Fatal("seq 43 must not be a duplicate")
	}
}

func TestGamingStatsSwitch(t *testing.T) {
	s := &GamingStats{}
	if s.ShouldSwitch() {
		t.Fatal("fresh stats must not trigger a switch")
	}
	// High RTT triggers a switch.
	for i := 0; i < 5; i++ {
		s.RecordRTT(200)
	}
	if !s.ShouldSwitch() {
		t.Fatal("RTT 200ms must trigger a switch")
	}
	// Loss > 3% triggers a switch.
	s2 := &GamingStats{}
	for i := 0; i < 100; i++ {
		s2.RecordSent()
	}
	for i := 0; i < 5; i++ {
		s2.RecordLost()
	}
	if !s2.ShouldSwitch() {
		t.Fatalf("5%% loss must trigger a switch, got %.2f%%", s2.Snapshot().LossPct)
	}
	s2.NoteSwitch("subflow-1")
	if s2.Snapshot().BestPath != "subflow-1" || s2.Snapshot().Switches != 1 {
		t.Errorf("NoteSwitch not recorded: %+v", s2.Snapshot())
	}
}

func TestXORFECRoundTrip(t *testing.T) {
	shards := [][]byte{
		[]byte("game-packet-one-0123456789"),
		[]byte("game-packet-two-0123456789"),
		[]byte("game-packet-tre-0123456789"),
		[]byte("game-packet-for-0123456789"),
	}
	par := xorFECEncode(shards)
	// Lose shard 2 and rebuild it.
	lost := shards[2]
	shards[2] = nil
	rec := xorFECRecover(shards, par, 2)
	if string(rec[:len(lost)]) != string(lost) {
		t.Fatalf("FEC recovery failed: got %q want %q", rec[:len(lost)], lost)
	}
}

func TestJitterBuffer(t *testing.T) {
	j := newJitterBuffer(5 * time.Millisecond)
	defer j.Close()
	j.Push(1, []byte("hello"))
	// Not due yet (delay 5ms, immediate pop with tiny timeout fails).
	if _, ok := j.Pop(time.Millisecond); ok {
		t.Fatal("jitter buffer released a packet before its delay")
	}
	data, ok := j.Pop(100 * time.Millisecond)
	if !ok || string(data) != "hello" {
		t.Fatalf("jitter buffer did not deliver: ok=%v data=%q", ok, data)
	}
}

func TestGamingFactoryInfo(t *testing.T) {
	for _, name := range []string{"wg-gaming", "wggame"} {
		f := &gamingFactory{name: name}
		if f.Info().Name != name || !f.Info().Encrypted || !f.Info().SupportsUDP {
			t.Errorf("bad Info for %s: %+v", name, f.Info())
		}
	}
}
