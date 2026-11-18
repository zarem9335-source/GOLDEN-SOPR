// Package config: GOLDEN SOPR config. JSON file at /etc/golden-sopr/config.json
// (also ~/.golden-sopr/config.json). Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack - AGPL-3.0, own branding GOLDEN SOPR, golden theme.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Role string

const (
	RoleIran   Role = "iran"
	RoleKharej Role = "kharej"
)

// Presets: Eco / Balanced / Turbo / Gaming (new, lowest latency)
type Preset string

const (
	PresetEco      Preset = "eco"
	PresetBalanced Preset = "balanced"
	PresetTurbo    Preset = "turbo"
	PresetGaming   Preset = "gaming"
)

type Tunnel struct {
	Name       string            `json:"name"`
	Role       Role              `json:"role"`
	Transport  string            `json:"transport"` // tcp, tcp-mux, tcp-stealth, tcp-pck, udp, udp-kcp, udp-quic, ws, ws-mux, wss, wss-mux, xdi, grpc, hq, wg, wg-gaming, ss, dns, tls-camou, bond, naive, xhttp, reality
	IranAddr   string            `json:"iran_addr"`
	TunnelPort int               `json:"tunnel_port"`
	Ports      []string          `json:"ports"` // "8080=127.0.0.1:8081" or "8080" or "8080-8090"
	Token      string            `json:"token"`
	AcceptUDP  bool              `json:"accept_udp"`
	Preset     Preset            `json:"preset"`
	Fallback   []string          `json:"fallback,omitempty"` // transport fallback chain, new
	Extra      map[string]string `json:"extra,omitempty"`    // cert, sni, path, uuid, short_id, wg keys, game ports...
	// Gaming (wg-gaming / gaming preset)
	GamePorts    []int `json:"game_ports,omitempty"`
	MTU          int   `json:"mtu,omitempty"`
	KeepaliveSec int   `json:"keepalive_sec,omitempty"`
	DuplicateUDP bool  `json:"duplicate_udp,omitempty"` // send game UDP twice over 2 paths
	FEC          bool  `json:"fec,omitempty"`
	Enabled      bool  `json:"enabled"`
}

type WebPanel struct {
	Enabled  bool   `json:"enabled"`
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Telegram struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	OwnerID int64  `json:"owner_id"`
}

type Config struct {
	Tunnels  []Tunnel `json:"tunnels"`
	WebPanel WebPanel `json:"web_panel"`
	Telegram Telegram `json:"telegram"`
	DataDir  string   `json:"-"`
}

func DefaultPath() string {
	if p := os.Getenv("SOPR_CONFIG"); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return "/etc/golden-sopr/config.json"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".golden-sopr", "config.json")
}

func NewToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{DataDir: filepath.Dir(path)}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	c.DataDir = filepath.Dir(path)
	return &c, nil
}

func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Config) Find(name string) *Tunnel {
	for i := range c.Tunnels {
		if c.Tunnels[i].Name == name {
			return &c.Tunnels[i]
		}
	}
	return nil
}

func (c *Config) Upsert(t Tunnel) {
	for i := range c.Tunnels {
		if c.Tunnels[i].Name == t.Name {
			c.Tunnels[i] = t
			return
		}
	}
	c.Tunnels = append(c.Tunnels, t)
}

func (t *Tunnel) Validate() error {
	if t.Name == "" {
		return fmt.Errorf("tunnel name required")
	}
	if t.Token == "" {
		return fmt.Errorf("token required")
	}
	if t.TunnelPort < 1 || t.TunnelPort > 65535 {
		return fmt.Errorf("tunnel port out of range")
	}
	if _, ok := ValidTransports[t.Transport]; !ok {
		return fmt.Errorf("unknown transport %q", t.Transport)
	}
	if t.Role == RoleIran && t.IranAddr == "" {
		t.IranAddr = "0.0.0.0"
	}
	return nil
}

// ValidTransports: all BackPack transports + new ones. wg-gaming is the
// gaming-optimised WireGuard transport (see transport/wggaming.go).
var ValidTransports = map[string]bool{
	"tcp": true, "tcp-mux": true, "tcp-stealth": true, "tcp-pck": true,
	"udp": true, "udp-kcp": true, "udp-quic": true,
	"ws": true, "ws-mux": true, "wss": true, "wss-mux": true, "xdi": true,
	"grpc": true, "hq": true, "wg": true, "wg-gaming": true, "wggame": true,
	"ss": true, "dns": true, "tls-camou": true, "bond": true,
	"naive": true, "xhttp": true, "reality": true,
}

// SetupLink encodes a tunnel as sopr://<base64 json> (like backpack://).
func (t *Tunnel) SetupLink() string {
	b, _ := json.Marshal(t)
	return "golden://" + base64.RawURLEncoding.EncodeToString(b)
}

func ParseSetupLink(link string) (*Tunnel, error) {
	link = strings.TrimSpace(link)
	link = strings.TrimPrefix(link, "golden://")
	link = strings.TrimPrefix(link, "sopr://")
	link = strings.TrimPrefix(link, "backpack://")
	b, err := base64.RawURLEncoding.DecodeString(link)
	if err != nil {
		return nil, err
	}
	var t Tunnel
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// GamePortsDefault: well-known game ports prioritised by wg-gaming.
var GamePortsDefault = []int{27015, 27016, 27017, 27018, 27019, 27020, 3074, 3478, 3479, 3480, 5222, 5795, 7000, 7100, 7200, 7300, 7400, 7500, 5060, 5062, 12000, 13000, 14000, 15000, 16000, 17000, 18000, 19000, 20000, 30000, 40000, 50000}
