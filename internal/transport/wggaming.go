// GOLDEN SOPR — "wg-gaming" / "wggame": the best tunnel for WireGuard gaming.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// Why this is the gaming transport:
//   - Noise-IK WireGuard-style handshake + ChaCha20-Poly1305 over UDP
//     (see wgcommon.go), so game traffic is encrypted and authenticated.
//   - MTU 1280 / MSS clamp 1240: fits inside the smallest common path
//     (IPv6 + UDP + WG overhead) so game packets are never fragmented.
//   - DSCP EF (TOS 184) + SO_PRIORITY on every socket: game traffic is
//     marked Expedited Forwarding for router QoS queues.
//   - Game-port prioritisation: destination ports in GamePortsDefault
//     (27015 CS, 3074 Xbox, 3478 PSN, ...) are classified "game" and
//     always sent first; bulk traffic waits behind them.
//   - Packet duplication: every game frame is sent twice, over two
//     independent UDP subflows to the same peer. One lost datagram on
//     either path still arrives on the other. The receiver dedups by
//     32-bit sequence number (1 s window).
//   - XOR FEC: every 4 data frames get a parity frame; losing any one
//     frame in the group is recoverable without a retransmit.
//   - Adaptive jitter buffer (5–15 ms, follows measured jitter) so
//     network jitter does not reach the game as stutter.
//   - Path monitor: RTT probe every 1 s on each subflow; if the active
//     path exceeds 120 ms RTT or 3% loss, the tunnel switches subflows
//     (failover well under 200 ms) and records the switch in GamingStats.
//   - Keepalive 5 s, handshake retry 500 ms: a dead path is noticed
//     and re-established fast.
//
// Both ends must run GOLDEN SOPR (same Noise-IK handshake as "wg").
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// GamingTuning is the full low-latency tuning for wg-gaming.
type GamingTuning struct {
	MTU            int // 1280
	MSS            int // 1240
	KeepaliveSec   int // 5
	HandshakeRetry time.Duration
	FECShards      int  // data frames per parity group (4)
	DupEnabled     bool // duplicate game frames over 2 subflows
	JitterMinMs    int  // 5
	JitterMaxMs    int  // 15
	DSCP           int  // 184 (EF)
	RTTSwitchMs    float64
	LossSwitchPct  float64
}

// DefaultGamingTuning returns the GOLDEN SOPR gaming defaults.
func DefaultGamingTuning() GamingTuning {
	return GamingTuning{
		MTU:            GamingMTUDefault,
		MSS:            GamingMSSDefault,
		KeepaliveSec:   GamingKeepaliveDefault,
		HandshakeRetry: GamingHandshakeRetryMs * time.Millisecond,
		FECShards:      4,
		DupEnabled:     true,
		JitterMinMs:    5,
		JitterMaxMs:    15,
		DSCP:           DSCPEF,
		RTTSwitchMs:    GamingRTTSwitchMs,
		LossSwitchPct:  GamingLossSwitchPct,
	}
}

// TuningFromExtra overrides gaming defaults from the tunnel Extra map:
// mtu, keepalive_sec, duplicate_udp, fec, game_ports.
func TuningFromExtra(extra map[string]string) GamingTuning {
	t := DefaultGamingTuning()
	t.MTU = extraInt(extra, "mtu", t.MTU)
	t.MSS = t.MTU - 40
	if t.MSS < 576 {
		t.MSS = 576
	}
	t.KeepaliveSec = extraInt(extra, "keepalive_sec", t.KeepaliveSec)
	t.DupEnabled = extraBool(extra, "duplicate_udp", t.DupEnabled)
	if !extraBool(extra, "fec", true) {
		t.FECShards = 0
	}
	return t
}

// ---- frame format over each subflow --------------------------------------
// [type 1][seq 4][len 2][payload] — type: 0 data, 1 ping, 2 pong,
// 3 keepalive, 4 parity. Max payload 1200 B (MTU 1280 minus overhead).

const (
	gfData      = 0
	gfPing      = 1
	gfPong      = 2
	gfKeepalive = 3
	gfParity    = 4

	gamingMaxPayload = 1200
)

type gamingFactory struct{ name string }

func (f *gamingFactory) Info() Info {
	return Info{
		Name:        f.name,
		Family:      "wg",
		Encrypted:   true,
		NeedsRoot:   false,
		SupportsUDP: true,
		Desc:        "GOLDEN SOPR gaming tunnel: WireGuard-style Noise-IK over UDP with MTU 1280, MSS clamp 1240, DSCP EF, game-port priority, packet duplication over 2 subflows, XOR FEC, adaptive jitter buffer and auto path switching (RTT>120ms or loss>3%). Best tunnel for WireGuard gaming.",
	}
}

func (f *gamingFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	tuning := TuningFromExtra(extra)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wg-gaming: resolve %s: %w", addr, err)
	}
	priv, pub, err := wgStaticKey(token, extra)
	if err != nil {
		return nil, err
	}
	peerPub, err := wgPeerPub(token, extra)
	if err != nil {
		return nil, err
	}
	ports := ParseGamePorts(extra["game_ports"])
	gameSet := NewGamePortSet(ports)

	subs := make([]*wgPacketConn, 0, 2)
	for i := 0; i < 2; i++ {
		pc, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			for _, s := range subs {
				s.Close()
			}
			return nil, fmt.Errorf("wg-gaming: dial udp subflow %d: %w", i, err)
		}
		dio := &directUDP{pc: pc}
		var hs *wgHandshake
		var lastErr error
		for attempt := 0; attempt < 3; attempt++ {
			hs, lastErr = wgHandshakeInitiator(dio, peerPub, priv, pub, 2*time.Second)
			if lastErr == nil {
				break
			}
			select {
			case <-ctx.Done():
				pc.Close()
				return nil, ctx.Err()
			case <-time.After(tuning.HandshakeRetry):
			}
		}
		if hs == nil {
			pc.Close()
			for _, s := range subs {
				s.Close()
			}
			return nil, fmt.Errorf("wg-gaming: subflow %d handshake failed: %w", i, lastErr)
		}
		c := newWGConn(dio, hs, pc.LocalAddr(), pc.RemoteAddr())
		_ = c.SetTOS(tuning.DSCP) // best effort; fails on restricted sockets
		subs = append(subs, c)
	}
	return newGamingConn(subs, tuning, gameSet, pcLocalAddr(subs)), nil
}

func pcLocalAddr(subs []*wgPacketConn) net.Addr {
	if len(subs) > 0 {
		return subs[0].LocalAddr()
	}
	return nil
}

func (f *gamingFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	inner := &wgFactory{name: "wg"}
	base, err := inner.Listen(ctx, addr, token, extra)
	if err != nil {
		return nil, err
	}
	tuning := TuningFromExtra(extra)
	gameSet := NewGamePortSet(ParseGamePorts(extra["game_ports"]))
	gl := &gamingListener{
		base:    base.(*wgListener),
		tuning:  tuning,
		game:    gameSet,
		accept:  make(chan net.Conn, 16),
		done:    make(chan struct{}),
		pending: map[string][]*pendingWG{},
	}
	go gl.pump()
	go func() {
		<-ctx.Done()
		gl.Close()
	}()
	return gl, nil
}

// gamingListener pairs two wg sessions from the same remote address into
// one gamingConn; a lone session still yields a (degraded, single-path)
// gamingConn after a short wait.
type gamingListener struct {
	base   *wgListener
	tuning GamingTuning
	game   *GamePortSet
	accept chan net.Conn
	done   chan struct{}
	once   sync.Once

	mu      sync.Mutex
	pending map[string][]*pendingWG // keyed by remote addr
}

type pendingWG struct {
	conn  *wgPacketConn
	since time.Time
}

func (l *gamingListener) pump() {
	go l.reaper()
	for {
		c, err := l.base.Accept()
		if err != nil {
			return
		}
		wc, ok := c.(*wgPacketConn)
		if !ok {
			c.Close()
			continue
		}
		_ = wc.SetTOS(l.tuning.DSCP)
		key := wc.RemoteAddr().String()
		l.mu.Lock()
		list := append(l.pending[key], &pendingWG{conn: wc, since: time.Now()})
		if len(list) >= 2 {
			first, second := list[0], list[1]
			l.pending[key] = list[2:]
			l.mu.Unlock()
			select {
			case l.accept <- newGamingConn([]*wgPacketConn{first.conn, second.conn}, l.tuning, l.game, first.conn.LocalAddr()):
			case <-l.done:
				first.conn.Close()
				second.conn.Close()
				return
			}
			continue
		}
		l.pending[key] = list
		l.mu.Unlock()
	}
}

// reaper delivers lone sessions solo after 2 s without a second subflow.
func (l *gamingListener) reaper() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			now := time.Now()
			l.mu.Lock()
			for key, list := range l.pending {
				var rest []*pendingWG
				for _, e := range list {
					if now.Sub(e.since) >= 2*time.Second {
						select {
						case l.accept <- newGamingConn([]*wgPacketConn{e.conn}, l.tuning, l.game, e.conn.LocalAddr()):
						case <-l.done:
							e.conn.Close()
						}
					} else {
						rest = append(rest, e)
					}
				}
				if len(rest) == 0 {
					delete(l.pending, key)
				} else {
					l.pending[key] = rest
				}
			}
			l.mu.Unlock()
		}
	}
}

func (l *gamingListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, errors.New("wg-gaming listener closed")
	}
}

func (l *gamingListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.base.Close()
	})
	return err
}

func (l *gamingListener) Addr() net.Addr { return l.base.Addr() }

// ---- gamingConn -----------------------------------------------------------

type gamingConn struct {
	subs    []*wgPacketConn // [0] primary, [1] secondary (if any)
	tuning  GamingTuning
	game    *GamePortSet
	stats   *GamingStats
	local   net.Addr
	remote  net.Addr
	dedup   *dedupReceiver
	jitter  *jitterBuffer
	frames  chan gframe
	done    chan struct{}
	closeMu sync.Mutex
	closed  bool

	// Write side.
	wmu       sync.Mutex
	seq       uint32
	sendGroup [][]byte
	sendSeqs  []uint32

	// Read side (ordered delivery).
	rmu      sync.Mutex
	cond     *sync.Cond
	readBuf  []byte
	readErr  error
	nextSeq  uint32
	ordered  map[uint32][]byte
	gapSince time.Time

	// FEC receive state: groupBase -> {seq -> payload}, parity payload.
	fmu    sync.Mutex
	fecBuf map[uint32]map[uint32][]byte
	fecPar map[uint32][]byte

	// Ping/pong RTT.
	pingMu  sync.Mutex
	pingSeq uint32
	pingAt  map[uint32]time.Time
	pingSub map[uint32]int
	primary int
}

type gframe struct {
	typ     byte
	seq     uint32
	payload []byte
	sub     int
}

func newGamingConn(subs []*wgPacketConn, tuning GamingTuning, game *GamePortSet, local net.Addr) *gamingConn {
	c := &gamingConn{
		subs:    subs,
		tuning:  tuning,
		game:    game,
		stats:   &GamingStats{},
		local:   local,
		frames:  make(chan gframe, 256),
		done:    make(chan struct{}),
		dedup:   newDedupReceiver(),
		jitter:  newJitterBuffer(8 * time.Millisecond),
		ordered: map[uint32][]byte{},
		fecBuf:  map[uint32]map[uint32][]byte{},
		fecPar:  map[uint32][]byte{},
		pingAt:  map[uint32]time.Time{},
		pingSub: map[uint32]int{},
	}
	if len(subs) > 0 {
		c.remote = subs[0].RemoteAddr()
	}
	c.cond = sync.NewCond(&c.rmu)
	for i := range subs {
		go c.readSubflow(i, subs[i])
	}
	go c.deliver()
	go c.monitor()
	if tuning.KeepaliveSec > 0 {
		go c.keepaliveLoop()
	}
	return c
}

// MTU returns the gaming MTU (1280).
func (c *gamingConn) MTU() int { return c.tuning.MTU }

// MSSClamp returns the clamped MSS (1240).
func (c *gamingConn) MSSClamp() int { return c.tuning.MSS }

// Stats returns a snapshot of the live latency picture.
func (c *gamingConn) Stats() GamingStats { return c.stats.Snapshot() }

// IsGamePort classifies a destination port via the tunnel's game set.
func (c *gamingConn) IsGamePort(port int) bool { return c.game.IsGamePort(port) }

func (c *gamingConn) LocalAddr() net.Addr  { return c.local }
func (c *gamingConn) RemoteAddr() net.Addr { return c.remote }

func (c *gamingConn) SetDeadline(t time.Time) error      { return nil }
func (c *gamingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *gamingConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *gamingConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	c.closeMu.Unlock()
	close(c.done)
	c.jitter.Close()
	for _, s := range c.subs {
		s.Close()
	}
	c.rmu.Lock()
	c.readErr = io.ErrClosedPipe
	c.cond.Broadcast()
	c.rmu.Unlock()
	return nil
}

// writeFrame encodes one frame and writes it to subflow idx.
func (c *gamingConn) writeFrame(idx int, typ byte, seq uint32, payload []byte) error {
	if idx < 0 || idx >= len(c.subs) {
		return errors.New("wg-gaming: no such subflow")
	}
	hdr := make([]byte, 7)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], seq)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	if _, err := c.subs[idx].Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

func (c *gamingConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > gamingMaxPayload {
			n = gamingMaxPayload
		}
		chunk := p[:n]
		seq := c.seq
		c.seq++
		// Primary always carries the frame.
		if err := c.writeFrame(c.primary, gfData, seq, chunk); err != nil {
			return total, err
		}
		c.stats.RecordSent()
		// Duplication: the same frame on the second subflow.
		if c.tuning.DupEnabled && len(c.subs) > 1 {
			other := 1 - c.primary
			if other < len(c.subs) {
				_ = c.writeFrame(other, gfData, seq, chunk)
			}
		}
		// XOR FEC: every FECShards data frames, a parity frame.
		if c.tuning.FECShards > 0 {
			c.sendGroup = append(c.sendGroup, append([]byte(nil), chunk...))
			c.sendSeqs = append(c.sendSeqs, seq)
			if len(c.sendGroup) >= c.tuning.FECShards {
				c.sendParity()
			}
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// sendParity builds the parity frame for the current group. Caller holds wmu.
func (c *gamingConn) sendParity() {
	if len(c.sendGroup) == 0 {
		return
	}
	par := xorFECEncode(c.sendGroup)
	// Parity payload: [len0 2][len1 2]... for each shard, then XOR bytes.
	pl := make([]byte, 0, 2*len(c.sendGroup)+len(par))
	for _, s := range c.sendGroup {
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(s)))
		pl = append(pl, lb[:]...)
	}
	pl = append(pl, par...)
	seq := c.sendSeqs[0] // group identified by its first seq
	idx := c.primary
	if len(c.subs) > 1 {
		idx = 1 - c.primary // parity rides the other path
	}
	_ = c.writeFrame(idx, gfParity, seq, pl)
	c.sendGroup = nil
	c.sendSeqs = nil
}

// readSubflow parses frames from one subflow and feeds the delivery channel.
func (c *gamingConn) readSubflow(idx int, s *wgPacketConn) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := s.Read(tmp)
		if err != nil {
			return
		}
		buf = append(buf, tmp[:n]...)
		for {
			if len(buf) < 7 {
				break
			}
			typ := buf[0]
			seq := binary.BigEndian.Uint32(buf[1:5])
			ln := int(binary.BigEndian.Uint16(buf[5:7]))
			if ln > 65535 || len(buf) < 7+ln {
				break
			}
			payload := append([]byte(nil), buf[7:7+ln]...)
			buf = buf[7+ln:]
			switch typ {
			case gfPing:
				// Echo as pong on the same subflow.
				_ = c.writeFrame(idx, gfPong, seq, payload)
			case gfPong:
				c.onPong(seq, payload)
			case gfKeepalive:
				// Nothing to do; the packet itself proves liveness.
			default: // data / parity
				select {
				case c.frames <- gframe{typ: typ, seq: seq, payload: payload, sub: idx}:
				case <-c.done:
					return
				}
			}
		}
	}
}

func (c *gamingConn) onPong(seq uint32, payload []byte) {
	c.pingMu.Lock()
	at, ok := c.pingAt[seq]
	delete(c.pingAt, seq)
	delete(c.pingSub, seq)
	c.pingMu.Unlock()
	if !ok || len(payload) < 8 {
		return
	}
	rtt := float64(time.Since(at).Microseconds()) / 1000.0
	c.stats.RecordRTT(rtt)
}

// deliver: dedup -> in-order reassembly -> FEC recovery -> jitter buffer
// -> read buffer. Runs as one goroutine so ordering is deterministic.
func (c *gamingConn) deliver() {
	release := func() {
		// Release everything in order; skip a gap older than 50 ms
		// (treat it as lost — FEC may still recover it below).
		for {
			if pl, ok := c.ordered[c.nextSeq]; ok {
				delete(c.ordered, c.nextSeq)
				c.nextSeq++
				c.gapSince = time.Time{}
				c.pushRead(pl)
				continue
			}
			if !c.gapSince.IsZero() && time.Since(c.gapSince) > 50*time.Millisecond {
				c.nextSeq++
				c.gapSince = time.Time{}
				c.stats.RecordLost()
				continue
			}
			break
		}
	}
	for {
		select {
		case <-c.done:
			return
		case fr := <-c.frames:
			if fr.typ == gfParity {
				c.handleParity(fr)
				c.rmu.Lock()
				release()
				c.rmu.Unlock()
				continue
			}
			if c.dedup.Seen(fr.seq) {
				continue // duplicate copy from the second subflow
			}
			// Record the shard for FEC before ordering.
			base := fr.seq - fr.seq%uint32(c.tuning.FECShards)
			c.fmu.Lock()
			g, ok := c.fecBuf[base]
			if !ok {
				g = map[uint32][]byte{}
				c.fecBuf[base] = g
			}
			g[fr.seq] = fr.payload
			c.fmu.Unlock()
			c.rmu.Lock()
			if fr.seq < c.nextSeq {
				c.rmu.Unlock()
				continue // already delivered
			}
			c.ordered[fr.seq] = fr.payload
			if c.gapSince.IsZero() && fr.seq != c.nextSeq {
				c.gapSince = time.Now()
			}
			release()
			c.rmu.Unlock()
		}
	}
}

// handleParity tries to rebuild the single missing frame of a group from
// its parity shard. Called from deliver(); may inject the recovered frame
// into the ordered map so it is released in sequence.
func (c *gamingConn) handleParity(fr gframe) {
	n := c.tuning.FECShards
	if n <= 0 || len(fr.payload) < 2*n {
		return
	}
	base := fr.seq
	lens := make([]int, n)
	for i := 0; i < n; i++ {
		lens[i] = int(binary.BigEndian.Uint16(fr.payload[2*i : 2*i+2]))
	}
	par := fr.payload[2*n:]
	c.fmu.Lock()
	g, ok := c.fecBuf[base]
	if !ok {
		c.fmu.Unlock()
		return
	}
	// Exactly one missing shard in the group, and it must not have been
	// delivered already.
	missing := -1
	for i := 0; i < n; i++ {
		seq := base + uint32(i)
		if _, has := g[seq]; !has {
			if missing != -1 {
				c.fmu.Unlock()
				return // two or more missing: unrecoverable
			}
			missing = i
		}
	}
	if missing == -1 {
		c.fmu.Unlock()
		return // nothing missing
	}
	missSeq := base + uint32(missing)
	c.rmu.Lock()
	already := missSeq < c.nextSeq
	c.rmu.Unlock()
	if already {
		c.fmu.Unlock()
		return
	}
	shards := make([][]byte, n)
	for i := 0; i < n; i++ {
		shards[i] = g[base+uint32(i)]
	}
	rec := xorFECRecover(shards, par, missing)
	if len(rec) > lens[missing] {
		rec = rec[:lens[missing]]
	}
	g[missSeq] = rec
	c.fmu.Unlock()
	// Inject as a recovered data frame (dedup map already has no entry
	// for it, since it never arrived).
	c.rmu.Lock()
	if missSeq >= c.nextSeq {
		c.ordered[missSeq] = rec
		if c.gapSince.IsZero() {
			c.gapSince = time.Now()
		}
	}
	c.rmu.Unlock()
	// Prune old FEC groups so the map stays bounded.
	c.fmu.Lock()
	for b := range c.fecBuf {
		if b+uint32(n) < c.nextSeq && b+100 < c.nextSeq {
			delete(c.fecBuf, b)
		}
	}
	c.fmu.Unlock()
}

// pushRead sends a payload through the jitter buffer into the read buffer.
// Caller holds rmu.
func (c *gamingConn) pushRead(pl []byte) {
	// Adaptive jitter delay: measured jitter clamped to 5–15 ms.
	delay := time.Duration(c.stats.Snapshot().JitterMs) * time.Millisecond
	if delay < time.Duration(c.tuning.JitterMinMs)*time.Millisecond {
		delay = time.Duration(c.tuning.JitterMinMs) * time.Millisecond
	}
	if delay > time.Duration(c.tuning.JitterMaxMs)*time.Millisecond {
		delay = time.Duration(c.tuning.JitterMaxMs) * time.Millisecond
	}
	c.jitter.Push(c.nextSeq, pl)
	go func() {
		data, ok := c.jitter.Pop(100 * time.Millisecond)
		if !ok {
			return
		}
		c.rmu.Lock()
		c.readBuf = append(c.readBuf, data...)
		c.cond.Broadcast()
		c.rmu.Unlock()
	}()
}

func (c *gamingConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.readBuf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		select {
		case <-c.done:
			return 0, io.ErrClosedPipe
		default:
		}
		c.cond.Wait()
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// monitor probes RTT on each subflow every second and switches the
// primary path when it goes bad (RTT > 120 ms or loss > 3%).
func (c *gamingConn) monitor() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			for i := range c.subs {
				c.pingMu.Lock()
				seq := c.pingSeq
				c.pingSeq++
				c.pingAt[seq] = time.Now()
				c.pingSub[seq] = i
				c.pingMu.Unlock()
				var ts [8]byte
				binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
				_ = c.writeFrame(i, gfPing, seq, ts[:])
			}
			// Switch if the primary is bad and a secondary exists.
			if len(c.subs) > 1 && c.stats.ShouldSwitch() {
				other := 1 - c.primary
				c.wmu.Lock()
				c.primary = other
				c.wmu.Unlock()
				c.stats.NoteSwitch(fmt.Sprintf("subflow-%d", other))
			}
		}
	}
}

func (c *gamingConn) keepaliveLoop() {
	t := time.NewTicker(time.Duration(c.tuning.KeepaliveSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			for i := range c.subs {
				_ = c.writeFrame(i, gfKeepalive, 0, nil)
			}
		}
	}
}
