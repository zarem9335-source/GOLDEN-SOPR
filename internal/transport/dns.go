// GOLDEN SOPR — "dns" transport: DNS tunnel.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// Data is framed as [seq 4][len 2][payload], base32-encoded and split
// into ≤60-char DNS labels, carried as TXT queries under a token-derived
// subdomain: <b32>.<sha256(token)[:16]>.sopr.tunnel. The server answers
// each query with a TXT record carrying the next downstream frame
// (piggybacked), so one query/response round trip moves data both ways.
// Chunks are 150 bytes, stop-and-wait with 800 ms retransmit (x3).
//
// This is slow (~150 B/RTT) and only for last-resort paths where UDP 53
// is the only thing that passes. The token-derived suffix authenticates
// queries: the server silently ignores anything under another suffix.
// Listening on UDP 53 needs root or CAP_NET_BIND_SERVICE.
package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	dnsChunkPayload = 150
	dnsLabelMax     = 60
)

var dnsB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type dnsFactory struct{}

func (f *dnsFactory) Info() Info {
	return Info{
		Name:        "dns",
		Family:      "dns",
		Encrypted:   false,
		NeedsRoot:   true, // UDP 53 listener
		SupportsUDP: true,
		Desc:        "DNS tunnel: frames as base32 TXT queries under a token-derived subdomain, downstream piggybacked in TXT answers. Last-resort transport (~150 B/RTT). Server needs UDP 53 (root or CAP_NET_BIND_SERVICE).",
	}
}

func dnsSuffix(token, extraSuffix string) string {
	sum := sha256.Sum256([]byte(token))
	if extraSuffix == "" {
		extraSuffix = "sopr.tunnel"
	}
	return hex.EncodeToString(sum[:8]) + "." + strings.TrimSuffix(extraSuffix, ".")
}

// ---- DNS wire helpers ----------------------------------------------------

func dnsEncodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func dnsDecodeName(msg []byte, off int) (string, int, error) {
	var labels []string
	for {
		if off >= len(msg) {
			return "", 0, errors.New("dns: name overruns packet")
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 == 0xc0 {
			// Compression pointer: follow it (response echo only).
			if off >= len(msg) {
				return "", 0, errors.New("dns: bad pointer")
			}
			ptr := int(l&0x3f)<<8 | int(msg[off])
			off++
			name, _, err := dnsDecodeName(msg, ptr)
			if err != nil {
				return "", 0, err
			}
			labels = append(labels, strings.Split(name, ".")...)
			break
		}
		if off+l > len(msg) {
			return "", 0, errors.New("dns: label overruns packet")
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), off, nil
}

func dnsBuildQuery(id uint16, qname string) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	q := append(hdr, dnsEncodeName(qname)...)
	q = append(q, 0, 16, 0, 1) // QTYPE TXT, QCLASS IN
	return q
}

// dnsParseQuery returns id, qname, qtype and the raw question section.
func dnsParseQuery(msg []byte) (uint16, string, uint16, []byte, error) {
	if len(msg) < 12 {
		return 0, "", 0, nil, errors.New("dns: short packet")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	qd := binary.BigEndian.Uint16(msg[4:6])
	if qd != 1 {
		return 0, "", 0, nil, errors.New("dns: expected exactly 1 question")
	}
	name, off, err := dnsDecodeName(msg, 12)
	if err != nil {
		return 0, "", 0, nil, err
	}
	if off+4 > len(msg) {
		return 0, "", 0, nil, errors.New("dns: short question")
	}
	qtype := binary.BigEndian.Uint16(msg[off : off+2])
	return id, name, qtype, msg[12 : off+4], nil
}

func dnsBuildTXTResponse(id uint16, question []byte, txt string) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // QR + RD + RA
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 1)             // ANCOUNT
	out := append(append(hdr, question...), 0xc0, 0x0c) // NAME pointer to QNAME
	out = append(out, 0, 16, 0, 1)                      // TYPE TXT, CLASS IN
	out = append(out, 0, 0, 0, 0)                       // TTL 0
	// RDATA: one or more <len><string> chunks.
	var rdata []byte
	for len(txt) > 0 {
		n := len(txt)
		if n > 255 {
			n = 255
		}
		rdata = append(rdata, byte(n))
		rdata = append(rdata, txt[:n]...)
		txt = txt[n:]
	}
	if len(rdata) == 0 {
		rdata = []byte{0} // empty TXT
	}
	var rl [2]byte
	binary.BigEndian.PutUint16(rl[:], uint16(len(rdata)))
	out = append(out, rl[:]...)
	return append(out, rdata...)
}

// dnsParseTXTResponse extracts the TXT strings from a response.
func dnsParseTXTResponse(msg []byte) (string, error) {
	if len(msg) < 12 {
		return "", errors.New("dns: short response")
	}
	an := binary.BigEndian.Uint16(msg[6:8])
	if an == 0 {
		return "", nil
	}
	_, off, err := dnsDecodeName(msg, 12)
	if err != nil {
		return "", err
	}
	off += 4 // QTYPE + QCLASS
	if off >= len(msg) {
		return "", nil
	}
	_, off, err = dnsDecodeName(msg, off)
	if err != nil {
		return "", err
	}
	if off+10 > len(msg) {
		return "", errors.New("dns: short answer")
	}
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	off += 10
	if off+rdlen > len(msg) {
		return "", errors.New("dns: short rdata")
	}
	rdata := msg[off : off+rdlen]
	var sb strings.Builder
	for len(rdata) > 0 {
		n := int(rdata[0])
		rdata = rdata[1:]
		if n > len(rdata) {
			break
		}
		sb.Write(rdata[:n])
		rdata = rdata[n:]
	}
	return sb.String(), nil
}

// ---- framing ---------------------------------------------------------------

func dnsFrame(seq uint32, payload []byte) []byte {
	out := make([]byte, 6+len(payload))
	binary.BigEndian.PutUint32(out[0:4], seq)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	copy(out[6:], payload)
	return out
}

func dnsUnframe(frame []byte) (uint32, []byte, error) {
	if len(frame) < 6 {
		return 0, nil, errors.New("dns: short frame")
	}
	seq := binary.BigEndian.Uint32(frame[0:4])
	ln := int(binary.BigEndian.Uint16(frame[4:6]))
	if len(frame) < 6+ln {
		return 0, nil, errors.New("dns: truncated frame")
	}
	return seq, frame[6 : 6+ln], nil
}

func dnsFrameToName(frame []byte, suffix string) string {
	enc := strings.ToLower(dnsB32.EncodeToString(frame))
	var labels []string
	for len(enc) > 0 {
		n := len(enc)
		if n > dnsLabelMax {
			n = dnsLabelMax
		}
		labels = append(labels, enc[:n])
		enc = enc[n:]
	}
	labels = append(labels, suffix)
	return strings.Join(labels, ".")
}

func dnsNameToFrame(name, suffix string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(name), "."+strings.ToLower(suffix))
	name = strings.TrimSuffix(name, strings.ToLower(suffix))
	enc := strings.ReplaceAll(name, ".", "")
	enc = strings.ToUpper(enc)
	return dnsB32.DecodeString(enc)
}

// ---- conn ------------------------------------------------------------------

type dnsConn struct {
	mu     sync.Mutex
	cond   *sync.Cond
	inBuf  []byte
	outQ   [][]byte
	seq    uint32
	seen   map[uint32]bool
	done   chan struct{}
	closed bool
	local  net.Addr
	remote net.Addr
	suffix string
	pc     *net.UDPConn // client only
	srv    *dnsListener // server only
	peer   *net.UDPAddr // server only
}

func newDNSConn(local, remote net.Addr, suffix string) *dnsConn {
	c := &dnsConn{local: local, remote: remote, suffix: suffix, seen: map[uint32]bool{}, done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *dnsConn) deliver(frame []byte) {
	seq, payload, err := dnsUnframe(frame)
	if err != nil || len(payload) == 0 {
		return
	}
	c.mu.Lock()
	if c.seen[seq] {
		c.mu.Unlock()
		return
	}
	c.seen[seq] = true
	c.inBuf = append(c.inBuf, payload...)
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *dnsConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.inBuf) == 0 {
		if c.closed {
			return 0, errors.New("dns conn closed")
		}
		c.cond.Wait()
	}
	n := copy(p, c.inBuf)
	c.inBuf = c.inBuf[n:]
	return n, nil
}

func (c *dnsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("dns conn closed")
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > dnsChunkPayload {
			n = dnsChunkPayload
		}
		c.outQ = append(c.outQ, dnsFrame(c.seq, p[:n]))
		c.seq++
		p = p[n:]
		total += n
	}
	c.cond.Broadcast()
	return total, nil
}

func (c *dnsConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	if c.pc != nil {
		return c.pc.Close()
	}
	return nil
}

func (c *dnsConn) LocalAddr() net.Addr                { return c.local }
func (c *dnsConn) RemoteAddr() net.Addr               { return c.remote }
func (c *dnsConn) SetDeadline(t time.Time) error      { return nil }
func (c *dnsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dnsConn) SetWriteDeadline(t time.Time) error { return nil }

// popOut returns the next outbound frame, or nil.
func (c *dnsConn) popOut() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.outQ) == 0 {
		return nil
	}
	f := c.outQ[0]
	c.outQ = c.outQ[1:]
	return f
}

// ---- client ----------------------------------------------------------------

func (f *dnsFactory) Dial(ctx context.Context, addr, token string, extra map[string]string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns: resolve %s: %w", addr, err)
	}
	pc, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	suffix := dnsSuffix(token, extra["dns_suffix"])
	c := newDNSConn(pc.LocalAddr(), pc.RemoteAddr(), suffix)
	c.pc = pc
	go c.clientPump()
	return c, nil
}

// clientPump: stop-and-wait — one query per chunk, retransmit x3 on
// timeout; an empty query every 5 s polls for downstream data.
func (c *dnsConn) clientPump() {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	tmp := make([]byte, 65535)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		frame := c.popOut()
		if frame == nil {
			// Poll for downstream data.
			select {
			case <-c.done:
				return
			case <-time.After(5 * time.Second):
			}
			frame = dnsFrame(c.seq, nil)
			c.seq++
		}
		qname := dnsFrameToName(frame, c.suffix)
		var downstream []byte
		for attempt := 0; attempt < 3; attempt++ {
			id := uint16(rnd.Intn(65536))
			if _, err := c.pc.Write(dnsBuildQuery(id, qname)); err != nil {
				return
			}
			_ = c.pc.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
			n, err := c.pc.Read(tmp)
			if err != nil {
				continue // timeout: retransmit
			}
			txt, err := dnsParseTXTResponse(tmp[:n])
			if err != nil || txt == "" {
				break // no downstream data in this answer
			}
			downstream, err = dnsNameToFrame(txt, c.suffix)
			if err != nil {
				// TXT carries raw base32 without the suffix.
				downstream, err = dnsB32.DecodeString(strings.ToUpper(txt))
				if err != nil {
					downstream = nil
				}
			}
			break
		}
		if downstream != nil {
			c.deliver(downstream)
		}
	}
}

// ---- server ----------------------------------------------------------------

type dnsListener struct {
	pc       *net.UDPConn
	token    string
	suffix   string
	acceptCh chan net.Conn
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	peers    map[string]*dnsConn
}

func (f *dnsFactory) Listen(ctx context.Context, addr, token string, extra map[string]string) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns: resolve %s: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dns: listen udp 53 needs root/CAP_NET_BIND_SERVICE: %w", err)
	}
	l := &dnsListener{
		pc: pc, token: token,
		suffix:   dnsSuffix(token, extra["dns_suffix"]),
		acceptCh: make(chan net.Conn, 16),
		done:     make(chan struct{}),
		peers:    map[string]*dnsConn{},
	}
	go l.serve()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return l, nil
}

func (l *dnsListener) serve() {
	tmp := make([]byte, 65535)
	for {
		n, src, err := l.pc.ReadFromUDP(tmp)
		if err != nil {
			return
		}
		id, qname, qtype, question, err := dnsParseQuery(tmp[:n])
		if err != nil || qtype != 16 {
			continue
		}
		// Only answer queries under our token-derived suffix.
		if !strings.HasSuffix(strings.ToLower(qname), "."+strings.ToLower(l.suffix)) &&
			!strings.EqualFold(qname, l.suffix) {
			continue
		}
		frame, err := dnsNameToFrame(qname, l.suffix)
		if err != nil {
			continue
		}
		l.mu.Lock()
		c, ok := l.peers[src.String()]
		if !ok {
			c = newDNSConn(l.pc.LocalAddr(), src, l.suffix)
			c.srv = l
			c.peer = src
			l.peers[src.String()] = c
			l.mu.Unlock()
			select {
			case l.acceptCh <- c:
			case <-l.done:
				return
			}
		} else {
			l.mu.Unlock()
		}
		c.deliver(frame)
		// Piggyback the next downstream frame in the TXT answer.
		down := c.popOut()
		var txt string
		if down != nil {
			txt = strings.ToLower(dnsB32.EncodeToString(down))
		}
		resp := dnsBuildTXTResponse(id, question, txt)
		_, _ = l.pc.WriteToUDP(resp, src)
	}
}

func (l *dnsListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.done:
		return nil, errors.New("dns listener closed")
	}
}

func (l *dnsListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.pc.Close()
	})
	return err
}

func (l *dnsListener) Addr() net.Addr { return l.pc.LocalAddr() }
