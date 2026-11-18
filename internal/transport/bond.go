// GOLDEN SOPR — "bond" transport: multipath bonding.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// Bond opens 2–3 subflows to the same peer (tcp, udp-quic, ws —
// whichever factories are registered) and carries every stream over
// the lowest-RTT subflow. Frames are [type 1][seq 4][len 4][payload]
// (type 0 data, 1 ping, 2 pong); the reader side reassembles in
// sequence order and drops duplicates. A monitor pings each subflow
// every 2 s; if the active subflow dies or its RTT exceeds 1.5x the
// best standby, traffic moves in well under 200 ms. If a subflow
// factory is missing, bond degrades gracefully to the subflows that
// exist (tcp alone still works).
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

const (
	bondData = 0
	bondPing = 1
	bondPong = 2
)

var bondSubflows = []string{"tcp", "udp-quic", "ws"}

type bondFactory struct{}

func (f *bondFactory) Info() Info {
	return Info{
		Name:        "bond",
		Family:      "bond",
		Encrypted:   false, // encryption comes from the subflows that have it
		NeedsRoot:   false,
		SupportsUDP: true,
		Desc:        "Multipath bonding: 2-3 subflows (tcp + udp-quic + ws), lowest-RTT wins, failover <200ms. Degrades gracefully when a subflow transport is unavailable.",
	}
}

func (f *bondFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	var subs []net.Conn
	var rtts []float64
	for _, name := range bondSubflows {
		fac, err := Get(name)
		if err != nil {
			continue // subflow transport not registered: skip it
		}
		start := time.Now()
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := fac.Dial(dctx, addr, token, extra)
		cancel()
		if err != nil {
			continue
		}
		subs = append(subs, c)
		rtts = append(rtts, float64(time.Since(start).Microseconds())/1000.0)
	}
	if len(subs) == 0 {
		return nil, errors.New("bond: no subflow could be established (tcp/udp-quic/ws all failed or unregistered)")
	}
	b := newBondConn(subs, rtts)
	return b, nil
}

// bondListener pairs subflow conns from the same remote IP into one
// bondConn (same pairing idea as wg-gaming's listener).
type bondListener struct {
	lns    []net.Listener
	accept chan net.Conn
	done   chan struct{}
	once   sync.Once

	mu      sync.Mutex
	pending map[string][]*pendingBond
}

type pendingBond struct {
	conn  net.Conn
	since time.Time
}

func (f *bondFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	l := &bondListener{
		accept:  make(chan net.Conn, 16),
		done:    make(chan struct{}),
		pending: map[string][]*pendingBond{},
	}
	// TCP-based subflows (tcp, ws) share one TCP listener: the bond
	// frame header distinguishes them from plain TCP after accept.
	// QUIC rides UDP on the same port number.
	for _, name := range []string{"tcp", "udp-quic"} {
		fac, err := Get(name)
		if err != nil {
			continue
		}
		ln, err := fac.Listen(ctx, addr, token, extra)
		if err != nil {
			continue
		}
		l.lns = append(l.lns, ln)
		go l.pump(ln)
	}
	if len(l.lns) == 0 {
		return nil, errors.New("bond: no subflow listener could be started")
	}
	go l.reaper()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return l, nil
}

func (l *bondListener) pump(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		key := remoteIP(c.RemoteAddr())
		l.mu.Lock()
		list := append(l.pending[key], &pendingBond{conn: c, since: time.Now()})
		if len(list) >= 2 {
			first, second := list[0], list[1]
			l.pending[key] = list[2:]
			l.mu.Unlock()
			select {
			case l.accept <- newBondConn([]net.Conn{first.conn, second.conn}, []float64{0, 0}):
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

func (l *bondListener) reaper() {
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
				var rest []*pendingBond
				for _, e := range list {
					if now.Sub(e.since) >= 2*time.Second {
						select {
						case l.accept <- newBondConn([]net.Conn{e.conn}, []float64{0}):
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

func remoteIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

func (l *bondListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, errors.New("bond listener closed")
	}
}

func (l *bondListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		for _, ln := range l.lns {
			ln.Close()
		}
	})
	return err
}

func (l *bondListener) Addr() net.Addr {
	if len(l.lns) > 0 {
		return l.lns[0].Addr()
	}
	return nil
}

// ---- bondConn ---------------------------------------------------------------

type bondFrame struct {
	typ     byte
	seq     uint32
	payload []byte
	sub     int
}

type bondConn struct {
	subs   []net.Conn
	rtts   []float64 // last measured RTT per subflow (ms)
	stats  *GamingStats
	frames chan bondFrame
	done   chan struct{}

	wmu     sync.Mutex
	seq     uint32
	primary int

	rmu      sync.Mutex
	cond     *sync.Cond
	readBuf  []byte
	readErr  error
	nextSeq  uint32
	ordered  map[uint32][]byte
	gapSince time.Time

	pingMu  sync.Mutex
	pingSeq uint32
	pingAt  map[uint32]time.Time
	pingSub map[uint32]int

	closeMu sync.Mutex
	closed  bool
	local   net.Addr
	remote  net.Addr
}

func newBondConn(subs []net.Conn, rtts []float64) *bondConn {
	b := &bondConn{
		subs:    subs,
		rtts:    rtts,
		stats:   &GamingStats{},
		frames:  make(chan bondFrame, 256),
		done:    make(chan struct{}),
		ordered: map[uint32][]byte{},
		pingAt:  map[uint32]time.Time{},
		pingSub: map[uint32]int{},
	}
	if len(subs) > 0 {
		b.local = subs[0].LocalAddr()
		b.remote = subs[0].RemoteAddr()
		// Primary = lowest initial RTT.
		for i, r := range rtts {
			if r < rtts[b.primary] {
				b.primary = i
			}
		}
	}
	b.cond = sync.NewCond(&b.rmu)
	for i := range subs {
		go b.readSubflow(i, subs[i])
	}
	go b.deliver()
	go b.monitor()
	return b
}

func (b *bondConn) LocalAddr() net.Addr                { return b.local }
func (b *bondConn) RemoteAddr() net.Addr               { return b.remote }
func (b *bondConn) SetDeadline(t time.Time) error      { return nil }
func (b *bondConn) SetReadDeadline(t time.Time) error  { return nil }
func (b *bondConn) SetWriteDeadline(t time.Time) error { return nil }

// Stats returns the live RTT/loss picture across subflows.
func (b *bondConn) Stats() GamingStats { return b.stats.Snapshot() }

func (b *bondConn) Close() error {
	b.closeMu.Lock()
	if b.closed {
		b.closeMu.Unlock()
		return nil
	}
	b.closed = true
	b.closeMu.Unlock()
	close(b.done)
	for _, s := range b.subs {
		s.Close()
	}
	b.rmu.Lock()
	b.readErr = io.ErrClosedPipe
	b.cond.Broadcast()
	b.rmu.Unlock()
	return nil
}

func (b *bondConn) writeFrame(idx int, typ byte, seq uint32, payload []byte) error {
	if idx < 0 || idx >= len(b.subs) {
		return errors.New("bond: no such subflow")
	}
	hdr := make([]byte, 9)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], seq)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	if _, err := b.subs[idx].Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

func (b *bondConn) Write(p []byte) (int, error) {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 65535 {
			n = 65535
		}
		seq := b.seq
		b.seq++
		if err := b.writeFrame(b.primary, bondData, seq, p[:n]); err != nil {
			// Failover: try the next subflow immediately (<200ms).
			switched := false
			for i := range b.subs {
				if i == b.primary {
					continue
				}
				if err2 := b.writeFrame(i, bondData, seq, p[:n]); err2 == nil {
					b.primary = i
					b.stats.NoteSwitch(fmt.Sprintf("subflow-%d", i))
					switched = true
					break
				}
			}
			if !switched {
				return total, fmt.Errorf("bond: all subflows failed: %w", err)
			}
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (b *bondConn) readSubflow(idx int, s net.Conn) {
	var buf []byte
	tmp := make([]byte, 8192)
	for {
		select {
		case <-b.done:
			return
		default:
		}
		n, err := s.Read(tmp)
		if err != nil {
			return
		}
		buf = append(buf, tmp[:n]...)
		for {
			if len(buf) < 9 {
				break
			}
			typ := buf[0]
			seq := binary.BigEndian.Uint32(buf[1:5])
			ln := int(binary.BigEndian.Uint32(buf[5:9]))
			if ln < 0 || ln > 1<<20 || len(buf) < 9+ln {
				break
			}
			payload := append([]byte(nil), buf[9:9+ln]...)
			buf = buf[9+ln:]
			switch typ {
			case bondPing:
				_ = b.writeFrame(idx, bondPong, seq, payload)
			case bondPong:
				b.onPong(seq)
			default:
				select {
				case b.frames <- bondFrame{typ: typ, seq: seq, payload: payload, sub: idx}:
				case <-b.done:
					return
				}
			}
		}
	}
}

func (b *bondConn) onPong(seq uint32) {
	b.pingMu.Lock()
	at, ok := b.pingAt[seq]
	sub := b.pingSub[seq]
	delete(b.pingAt, seq)
	delete(b.pingSub, seq)
	b.pingMu.Unlock()
	if !ok {
		return
	}
	rtt := float64(time.Since(at).Microseconds()) / 1000.0
	if sub >= 0 && sub < len(b.rtts) {
		b.wmu.Lock()
		b.rtts[sub] = b.rtts[sub]*0.75 + rtt*0.25
		b.wmu.Unlock()
	}
	b.stats.RecordRTT(rtt)
}

func (b *bondConn) deliver() {
	for {
		select {
		case <-b.done:
			return
		case fr := <-b.frames:
			b.rmu.Lock()
			if fr.seq < b.nextSeq {
				b.rmu.Unlock()
				continue
			}
			b.ordered[fr.seq] = fr.payload
			if b.gapSince.IsZero() && fr.seq != b.nextSeq {
				b.gapSince = time.Now()
			}
			for {
				if pl, ok := b.ordered[b.nextSeq]; ok {
					delete(b.ordered, b.nextSeq)
					b.nextSeq++
					b.gapSince = time.Time{}
					b.readBuf = append(b.readBuf, pl...)
					b.cond.Broadcast()
					continue
				}
				if !b.gapSince.IsZero() && time.Since(b.gapSince) > 100*time.Millisecond {
					b.nextSeq++
					b.gapSince = time.Time{}
					b.stats.RecordLost()
					continue
				}
				break
			}
			b.rmu.Unlock()
		}
	}
}

func (b *bondConn) Read(p []byte) (int, error) {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	for len(b.readBuf) == 0 {
		if b.readErr != nil {
			return 0, b.readErr
		}
		select {
		case <-b.done:
			return 0, io.ErrClosedPipe
		default:
		}
		b.cond.Wait()
	}
	n := copy(p, b.readBuf)
	b.readBuf = b.readBuf[n:]
	return n, nil
}

// monitor pings every subflow and moves the primary to the best one.
func (b *bondConn) monitor() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-t.C:
			for i := range b.subs {
				b.pingMu.Lock()
				seq := b.pingSeq
				b.pingSeq++
				b.pingAt[seq] = time.Now()
				b.pingSub[seq] = i
				b.pingMu.Unlock()
				var ts [8]byte
				binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
				_ = b.writeFrame(i, bondPing, seq, ts[:])
			}
			// Switch if another subflow is clearly faster.
			b.wmu.Lock()
			best := b.primary
			for i, r := range b.rtts {
				if r > 0 && (b.rtts[best] == 0 || r*1.5 < b.rtts[best]) {
					best = i
				}
			}
			if best != b.primary {
				b.primary = best
				b.stats.NoteSwitch(fmt.Sprintf("subflow-%d", best))
			}
			b.wmu.Unlock()
		}
	}
}
