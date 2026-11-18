package cmd

import (
	"fmt"
	"strings"

	"github.com/soprpack/soprpack/internal/config"
)

// ApplyLink parses a sopr:// (or backpack://) setup link, validates it,
// upserts it into the config and saves. Returns the tunnel.
func ApplyLink(link, cfgPath string) (*config.Tunnel, error) {
	// golden:// is the display scheme; the config parser accepts
	// sopr:// and backpack://, so normalise golden:// to sopr:// here
	// (config contract untouched).
	link = strings.TrimSpace(link)
	link = strings.TrimPrefix(link, "golden://")
	if link != "" && !strings.HasPrefix(link, "sopr://") && !strings.HasPrefix(link, "backpack://") {
		link = "sopr://" + link
	}
	t, err := config.ParseSetupLink(link)
	if err != nil {
		return nil, fmt.Errorf("invalid setup link: %w", err)
	}
	if t.Token == "" {
		return nil, fmt.Errorf("setup link has no token")
	}
	if err := t.Validate(); err != nil {
		return nil, fmt.Errorf("tunnel in link is invalid: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	// A link created on Iran carries role=iran; on Kharej the tunnel must
	// run as client. Keep the link's role unless the user overrides it —
	// the Kharej wizard flips it explicitly before calling ApplyLink.
	cfg.Upsert(*t)
	if err := cfg.Save(cfgPath); err != nil {
		return nil, err
	}
	return t, nil
}

// PrintTunnelSummary prints a one-screen summary (used after setup/link).
func PrintTunnelSummary(t *config.Tunnel) {
	fmt.Printf("\nTunnel: %s\n  Role:      %s\n  Transport: %s\n  Iran:      %s:%d\n  Ports:     %v\n  Preset:    %s\n  Accept UDP: %v\n",
		t.Name, t.Role, t.Transport, t.IranAddr, t.TunnelPort, t.Ports, t.Preset, t.AcceptUDP)
	if len(t.Fallback) > 0 {
		fmt.Printf("  Fallback:  %v\n", t.Fallback)
	}
	if t.Transport == "wg-gaming" || t.Preset == config.PresetGaming {
		fmt.Printf("  Gaming:    MTU %d, keepalive %ds, game ports %v, duplicate UDP %v, FEC %v\n",
			t.MTU, t.KeepaliveSec, t.GamePorts, t.DuplicateUDP, t.FEC)
	}
	fmt.Printf("  Setup Link: %s\n\n", goldenLink(t))
}

// goldenLink renders a tunnel's setup link with the golden:// scheme.
func goldenLink(t *config.Tunnel) string {
	return strings.Replace(t.SetupLink(), "sopr://", "golden://", 1)
}
