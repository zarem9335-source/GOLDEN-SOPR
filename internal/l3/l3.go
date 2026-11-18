// Package l3: GOLDEN SOPR direct layer-3 tunnel carriers.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// A direct L3 tunnel carries whole IP packets Iran <-> Kharej (unlike the
// reverse engine, which forwards individual TCP/UDP flows). Carriers:
//   - GRE: a kernel GRE tunnel via the `ip` command (needs root + iproute2).
//   - IPSpoof: raw IP packets with a spoofed source address (needs root).
//   - SNISpoof: a TLS ClientHello whose SNI names a cover host while the
//     TCP connection goes to the real peer (uTLS Chrome fingerprint).
//   - WG: the WireGuard-style L3 mode — the Noise-IK session from the
//     "wg" / "wg-gaming" transports bridged to a TUN device. This package
//     deliberately does NOT import internal/transport (that would be an
//     import cycle): it opens TUN itself and the caller wires the session.
//
// All of these need root on Linux. Every function that cannot run here
// returns a clear error saying so instead of silently doing nothing.
package l3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	tlsutls "github.com/refraction-networking/utls"
)

// Carrier is a direct L3 carrier type.
type Carrier string

const (
	CarrierGRE      Carrier = "gre"
	CarrierIPSpoof  Carrier = "ipspoof"
	CarrierSNISpoof Carrier = "snispoof"
	CarrierWG       Carrier = "wg"
)

// Config describes one direct L3 tunnel.
type Config struct {
	Carrier  Carrier
	LocalIP  string // local tunnel endpoint, e.g. 10.200.0.1
	RemoteIP string // remote tunnel endpoint, e.g. 10.200.0.2
	Remote   string // peer's public IP/host for GRE / WG
	Key      uint32 // GRE key (0 = none)
	MTU      int    // default 1400
	IfName   string // interface name, e.g. sopr0
	SpoofSrc string // IPSpoof: source address to put on packets
	CoverSNI string // SNISpoof: SNI to present (cover host)
	Token    string // WG: tunnel token for the Noise handshake
}

func (c Config) mtu() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return 1400
}

// SetupGRE creates a kernel GRE tunnel with the `ip` command and brings
// it up with the given tunnel addresses. Needs root + iproute2.
func SetupGRE(ctx context.Context, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("l3 gre: needs root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("l3 gre: `ip` (iproute2) not found: %w", err)
	}
	ifName := cfg.IfName
	if ifName == "" {
		ifName = "sopr-gre0"
	}
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// Remove a stale tunnel with the same name first (idempotent setup).
	_ = run("tunnel", "del", ifName)
	args := []string{"tunnel", "add", ifName, "mode", "gre", "local", cfg.LocalIP, "remote", cfg.Remote}
	if cfg.Key != 0 {
		args = append(args, "key", fmt.Sprint(cfg.Key))
	}
	if err := run(args...); err != nil {
		return err
	}
	if err := run("addr", "add", cfg.LocalIP+"/30", "dev", ifName); err != nil {
		return err
	}
	if err := run("link", "set", ifName, "mtu", fmt.Sprint(cfg.mtu()), "up"); err != nil {
		return err
	}
	return nil
}

// TeardownGRE removes a GRE tunnel created by SetupGRE.
func TeardownGRE(ctx context.Context, ifName string) error {
	if ifName == "" {
		ifName = "sopr-gre0"
	}
	cmd := exec.CommandContext(ctx, "ip", "tunnel", "del", ifName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip tunnel del %s: %w: %s", ifName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SpoofPacket sends one raw IPv4 packet with a spoofed source address.
// The payload must already be a complete IP packet (header + data).
// Needs root (raw socket) and a kernel that permits the source.
func SpoofPacket(src, dst string, packet []byte) error {
	if os.Geteuid() != 0 {
		return errors.New("l3 ipspoof: needs root (raw socket)")
	}
	sip := net.ParseIP(src)
	dip := net.ParseIP(dst)
	if sip == nil || dip == nil {
		return fmt.Errorf("l3 ipspoof: bad src/dst IP %q/%q", src, dst)
	}
	conn, err := net.Dial("ip4:raw", dip.String())
	if err != nil {
		return fmt.Errorf("l3 ipspoof: raw socket: %w", err)
	}
	defer conn.Close()
	// The kernel fills the IP header from the socket; set the source via
	// a raw socket bound to the spoofed address where permitted.
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("l3 ipspoof: write: %w", err)
	}
	return nil
}

// SNISpoof dials the peer's real address while presenting a cover SNI in
// the TLS ClientHello (uTLS Chrome fingerprint). The returned conn is a
// live TLS session to the peer — the cover host is only named, never
// connected to. The peer must terminate TLS with the cover SNI accepted.
func SNISpoof(ctx context.Context, realAddr, coverSNI string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", realAddr)
	if err != nil {
		return nil, fmt.Errorf("l3 snispoof: dial %s: %w", realAddr, err)
	}
	cfg := &tlsutls.Config{
		ServerName:         coverSNI,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	u := tlsutls.UClient(raw, cfg, tlsutls.HelloChrome_Auto)
	if err := u.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("l3 snispoof: handshake with SNI %s: %w", coverSNI, err)
	}
	return u, nil
}

// SNISpoofTLS is the same idea with the standard library TLS stack
// (no fingerprint camouflage — use SNISpoof for Chrome fingerprinting).
func SNISpoofTLS(ctx context.Context, realAddr, coverSNI string) (net.Conn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{ServerName: coverSNI, InsecureSkipVerify: true}, //nolint:gosec
	}
	return d.DialContext(ctx, "tcp", realAddr)
}

// OpenTUN opens /dev/net/tun for the WG L3 mode and returns the file and
// the kernel interface name. Callers bridge this fd to a wg session.
// Needs root + /dev/net/tun; otherwise returns a clear error.
func OpenTUN(name string) (*os.File, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("l3 wg: open /dev/net/tun: %w (need root + tun module)", err)
	}
	// TUNSETIFF via ioctl; layout matches struct ifreq on Linux.
	const (
		iffTun    = 0x0001
		iffNoPi   = 0x1000
		tunSetIff = 0x400454ca
	)
	var ifr [40]byte
	if name != "" {
		copy(ifr[:16], name)
	}
	ifr[16] = byte((iffTun | iffNoPi) & 0xff)
	ifr[17] = byte(((iffTun | iffNoPi) >> 8) & 0xff)
	if _, _, errno := ioctl(f.Fd(), tunSetIff, unsafe.Pointer(&ifr[0])); errno != 0 {
		f.Close()
		return nil, "", fmt.Errorf("l3 wg: TUNSETIFF: %v", errno)
	}
	ifName := strings.TrimRight(string(ifr[:16]), "\x00")
	return f, ifName, nil
}

// SetupWG documents the WG L3 wiring: the caller creates a wg/wg-gaming
// transport session (internal/transport) and bridges it to the TUN fd
// from OpenTUN (IP packets in, IP packets out). This function validates
// the config and opens TUN; the session itself lives in the transport.
func SetupWG(ctx context.Context, cfg Config) (*os.File, string, error) {
	if cfg.Token == "" {
		return nil, "", errors.New("l3 wg: token required for the Noise handshake")
	}
	ifName := cfg.IfName
	if ifName == "" {
		ifName = "sopr-wg0"
	}
	f, name, err := OpenTUN(ifName)
	if err != nil {
		return nil, "", err
	}
	// Bring the interface up with the tunnel address.
	mtu := cfg.mtu()
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("addr", "add", cfg.LocalIP+"/30", "dev", name); err != nil {
		f.Close()
		return nil, "", err
	}
	if err := run("link", "set", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		f.Close()
		return nil, "", err
	}
	return f, name, nil
}

// ioctl issues a raw ioctl on fd (Linux).
func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) (uintptr, uintptr, syscall.Errno) {
	r1, r2, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	return r1, r2, errno
}
