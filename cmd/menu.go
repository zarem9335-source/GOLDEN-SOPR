package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/soprpack/soprpack/internal/backup"
	"github.com/soprpack/soprpack/internal/config"
	"github.com/soprpack/soprpack/internal/linktest"
	"github.com/soprpack/soprpack/internal/monitor"
	"github.com/soprpack/soprpack/internal/telegram"
	"github.com/soprpack/soprpack/internal/transport"
	"github.com/soprpack/soprpack/internal/web"
)

var stdin = bufio.NewReader(os.Stdin)

// Gold theme (ANSI 38;5;220 = #FFD700 on dark).
const gold = "\x1b[38;5;220m"
const reset = "\x1b[0m"

func prompt(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptInt(label string, def int) int {
	s := prompt(label, strconv.Itoa(def))
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func promptBool(label string, def bool) bool {
	d := "y"
	if !def {
		d = "n"
	}
	s := strings.ToLower(prompt(label+" (y/n)", d))
	return s == "y" || s == "yes"
}

// transportNames returns registered transports, falling back to the
// config.ValidTransports list when no factory is registered yet.
func transportNames() []string {
	names := transport.Names()
	if len(names) == 0 {
		for n := range config.ValidTransports {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func pickTransport(def string) string {
	names := transportNames()
	fmt.Println("Transports:")
	for i, n := range names {
		mark := ""
		if n == def {
			mark = "  ← default"
		}
		fmt.Printf("  %2d. %s%s\n", i+1, n, mark)
	}
	fmt.Println("  wg-gaming = best for gaming WireGuard (lowest jitter, FEC + duplication)")
	s := prompt("Choose transport (name or number)", def)
	if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(names) {
		return names[n-1]
	}
	if _, ok := config.ValidTransports[s]; ok {
		return s
	}
	fmt.Printf("Unknown transport %q, using %s.\n", s, def)
	return def
}

func pickPreset(def config.Preset) config.Preset {
	fmt.Println("Presets: eco / balanced / turbo / gaming")
	s := strings.ToLower(prompt("Preset", string(def)))
	switch config.Preset(s) {
	case config.PresetEco, config.PresetBalanced, config.PresetTurbo, config.PresetGaming:
		return config.Preset(s)
	default:
		fmt.Printf("Unknown preset, using %s.\n", def)
		return def
	}
}

func parsePorts(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func applyGamingDefaults(t *config.Tunnel) {
	if t.Preset != config.PresetGaming && t.Transport != "wg-gaming" {
		return
	}
	if t.Transport == "" {
		t.Transport = "wg-gaming"
	}
	if t.MTU == 0 {
		t.MTU = 1280
	}
	if t.KeepaliveSec == 0 {
		t.KeepaliveSec = 5
	}
	if len(t.GamePorts) == 0 {
		t.GamePorts = config.GamePortsDefault
	}
	t.DuplicateUDP = true
	t.FEC = true
	t.AcceptUDP = true
}

// SetupIran runs the Iran-side wizard.
func SetupIran(cfgPath string) error {
	fmt.Println("\n\033[38;5;220m=== ✨ GOLDEN SOPR — Setup Iran (server side) ===\033[0m")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	t := config.Tunnel{Role: config.RoleIran, Enabled: true}
	t.Transport = pickTransport("tcp-mux")
	t.IranAddr = prompt("Iran IP or domain (detected IP is the default)", detectIP())
	t.TunnelPort = promptInt("Tunnel port", 4433)
	t.Ports = parsePorts(prompt("Forwarded ports (e.g. 8080=127.0.0.1:8081, 443)", "8080=127.0.0.1:8081"))
	t.Name = prompt("Tunnel name", "main")
	t.Token = prompt("Security token (Enter = generate)", "")
	if t.Token == "" {
		t.Token = config.NewToken()
		fmt.Println("Generated token:", t.Token)
	}
	t.AcceptUDP = promptBool("Carry UDP as well as TCP?", true)
	t.Preset = pickPreset(config.PresetBalanced)
	if t.Preset == config.PresetGaming {
		fmt.Println("Gaming preset: switching to wg-gaming — best for gaming WireGuard.")
		t.Transport = "wg-gaming"
	}
	// Optional fallback chain (comma-separated transports).
	fb := prompt("Fallback transports (comma-separated, Enter = none)", "")
	if fb != "" {
		t.Fallback = parsePorts(fb)
	}
	applyGamingDefaults(&t)
	if err := t.Validate(); err != nil {
		return fmt.Errorf("invalid tunnel: %w", err)
	}
	cfg.Upsert(t)
	if err := cfg.Save(cfgPath); err != nil {
		return err
	}
	fmt.Println("\n✅ Iran tunnel created. Copy this Setup Link to the Kharej server:")
	PrintTunnelSummary(&t)
	fmt.Println("Next: on Kharej run `sopr` → 2. Setup Kharej and paste the link.")
	return nil
}

// SetupKharej runs the Kharej-side wizard (link or manual).
func SetupKharej(cfgPath string) error {
	fmt.Println("\n\033[38;5;220m=== ✨ GOLDEN SOPR — Setup Kharej (client side) ===\033[0m")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	link := prompt("Paste Setup Link (sopr://…) — or Enter for manual setup", "")
	var t config.Tunnel
	if link != "" {
		got, err := config.ParseSetupLink(link)
		if err != nil {
			return fmt.Errorf("invalid setup link: %w", err)
		}
		t = *got
		t.Role = config.RoleKharej
		t.Name = prompt("Tunnel name", t.Name)
	} else {
		t = config.Tunnel{Role: config.RoleKharej, Enabled: true}
		t.Transport = pickTransport("tcp-mux")
		t.IranAddr = prompt("Iran IP or domain", "")
		t.TunnelPort = promptInt("Tunnel port (same as Iran)", 4433)
		t.Name = prompt("Tunnel name", "main")
		t.Token = prompt("Security token (same as Iran)", "")
		t.Preset = pickPreset(config.PresetBalanced)
		if t.Preset == config.PresetGaming {
			t.Transport = "wg-gaming"
		}
		applyGamingDefaults(&t)
	}
	t.Enabled = true
	applyGamingDefaults(&t)
	if err := t.Validate(); err != nil {
		return fmt.Errorf("invalid tunnel: %w", err)
	}
	cfg.Upsert(t)
	if err := cfg.Save(cfgPath); err != nil {
		return err
	}
	PrintTunnelSummary(&t)
	fmt.Printf("Start it with: sopr run --tunnel %s\n", t.Name)
	return nil
}

func detectIP() string {
	// Best-effort public IP; offline = empty (user types it).
	out, err := exec.Command("curl", "-fsSL", "--max-time", "5", "https://ifconfig.me").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// RunMenu is the interactive TUI (numbered text menu).
func RunMenu(cfgPath string) error {
	for {
		fmt.Println(gold + "✨ GOLDEN SOPR ✨" + reset + " — gold tunnel engine (v1.0.0)")
		fmt.Println(`
 1. Setup Iran
 2. Setup Kharej
 3. Manage tunnels
 4. Link Test
 5. Optimize (BBR + gaming)
 6. Backup / Restore
 7. Web Panel
 8. Telegram bot
 9. Update
 0. Exit`)
		choice := prompt("Choose", "0")
		var err error
		switch choice {
		case "1":
			err = SetupIran(cfgPath)
		case "2":
			err = SetupKharej(cfgPath)
		case "3":
			err = Manage(cfgPath)
		case "4":
			err = LinkTestMenu(cfgPath)
		case "5":
			err = OptimizeMenu()
		case "6":
			err = BackupMenu(cfgPath)
		case "7":
			err = WebPanelMenu(cfgPath)
		case "8":
			err = TelegramMenu(cfgPath)
		case "9":
			fmt.Println("Update: download the latest release and re-run install.sh (see README).")
		case "0":
			fmt.Println("Bye.")
			return nil
		default:
			fmt.Println("Unknown choice.")
		}
		if err != nil {
			fmt.Println("Error:", err)
		}
	}
}

// Manage lists tunnels and offers status / health / start / delete.
func Manage(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if len(cfg.Tunnels) == 0 {
		fmt.Println("No tunnels yet. Use 1. Setup Iran or 2. Setup Kharej.")
		return nil
	}
	for i, t := range cfg.Tunnels {
		fmt.Printf("%d. %s — %s %s %s:%d enabled=%v\n", i+1, t.Name, t.Role, t.Transport, t.IranAddr, t.TunnelPort, t.Enabled)
	}
	sel := promptInt("Select tunnel (0 = back)", 0)
	if sel < 1 || sel > len(cfg.Tunnels) {
		return nil
	}
	t := cfg.Tunnels[sel-1]
	fmt.Println("a. Health check   b. Start (run)   c. Delete   d. Back")
	switch strings.ToLower(prompt("Action", "d")) {
	case "a":
		HealthCheck(&t)
	case "b":
		return RunTunnel(cfgPath, t.Name)
	case "c":
		if promptBool("Delete "+t.Name+"?", false) {
			cfg.Tunnels = append(cfg.Tunnels[:sel-1], cfg.Tunnels[sel:]...)
			return cfg.Save(cfgPath)
		}
	}
	return nil
}

// LinkTestMenu measures the route and recommends a transport.
func LinkTestMenu(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	addr := prompt("Iran address to test (host:port)", "")
	if addr == "" && len(cfg.Tunnels) > 0 {
		t := cfg.Tunnels[0]
		addr = fmt.Sprintf("%s:%d", t.IranAddr, t.TunnelPort)
	}
	gaming := promptBool("Is this for gaming?", false)
	fmt.Printf("Measuring %s …\n", addr)
	r, err := linktest.Measure(addr, 5)
	if err != nil {
		rec, reason := linktest.RecommendForFiltered()
		fmt.Printf("Route unreachable: %v\nRecommendation: %s — %s\n", err, rec, reason)
		return nil
	}
	if gaming {
		r.Recommend, r.Reason = linktest.Recommend(r.LatencyMs, r.JitterMs, r.LossPct, true)
	}
	fmt.Printf("Latency: %.1f ms | Jitter: %.1f ms | Loss: %.1f%% | Probes: %d\n",
		r.LatencyMs, r.JitterMs, r.LossPct, r.Probes)
	fmt.Printf("Recommended transport: %s — %s\n", r.Recommend, r.Reason)
	fmt.Printf("Scores: %v\n", r.Scores)
	return nil
}

// OptimizeMenu applies BBR + gaming sysctls (needs root; otherwise it
// prints the commands so the user can run them).
func OptimizeMenu() error {
	cmds := [][]string{
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_fastopen=3"},
		{"sysctl", "-w", "net.core.rmem_max=26214400"},
		{"sysctl", "-w", "net.core.wmem_max=26214400"},
	}
	if os.Geteuid() != 0 {
		fmt.Println("Not root — run these as root for BBR + gaming tuning:")
		for _, c := range cmds {
			fmt.Println("  " + strings.Join(c, " "))
		}
		fmt.Println("Gaming tip: use the gaming preset / wg-gaming transport (MTU 1280, keepalive 5s).")
		return nil
	}
	failed := 0
	for _, c := range cmds {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err != nil {
			failed++
			fmt.Printf("$ %s → %s FAILED: %v\n", strings.Join(c, " "), strings.TrimSpace(string(out)), err)
		} else {
			fmt.Printf("$ %s → %s OK\n", strings.Join(c, " "), strings.TrimSpace(string(out)))
		}
	}
	if failed > 0 {
		fmt.Printf("Optimize: %d of %d sysctls failed (see FAILED above) — the rest were applied.\n", failed, len(cmds))
		return nil
	}
	fmt.Println("Optimize done: BBR + fq + TCP fastopen applied (gaming-friendly).")
	return nil
}

// BackupMenu creates or restores a backup zip.
func BackupMenu(cfgPath string) error {
	fmt.Println("a. Create backup   b. Restore backup")
	switch strings.ToLower(prompt("Action", "a")) {
	case "a":
		dst, err := backup.Backup(cfgPath, "")
		if err != nil {
			return err
		}
		fmt.Println("Backup written to:", dst)
	case "b":
		src := prompt("Backup zip path", "")
		p, err := backup.Restore(src, "")
		if err != nil {
			return err
		}
		fmt.Println("Restored config to:", p)
	}
	return nil
}

// WebPanelMenu starts the web panel in the foreground.
func WebPanelMenu(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	addr := cfg.WebPanel.Addr
	if addr == "" {
		addr = "127.0.0.1:2097"
	}
	prov := &web.Provider{
		ListTunnels: func() []config.Tunnel { c, _ := config.Load(cfgPath); return c.Tunnels },
		Config:      func() *config.Config { c, _ := config.Load(cfgPath); return c },
		Save:        func(c *config.Config) error { return c.Save(cfgPath) },
		Metrics:     func() map[string]any { return map[string]any{"uptime": time.Now().Format(time.RFC3339)} },
	}
	srv := web.New(addr, cfg.WebPanel.Username, cfg.WebPanel.Password, prov)
	fmt.Printf("\033[38;5;220mStarting GOLDEN SOPR web panel (first free port from %s)\033[0m  (user: %s — change the password in the config!)\nPress Ctrl+C to stop.\n", addr, srv.Username)
	return srv.ListenAndServe(context.Background())
}

// TelegramMenu starts the Telegram bot in the foreground.
func TelegramMenu(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.Telegram.Token == "" {
		fmt.Println("Telegram is not configured. Set token + owner_id in the config file, then retry.")
		return nil
	}
	bot := telegram.New(cfg.Telegram.Token, cfg.Telegram.OwnerID)
	bot.Tunnels = func() []config.Tunnel { c, _ := config.Load(cfgPath); return c.Tunnels }
	bot.IsUp = func(name string) bool { return false } // live state comes from monitor; see README
	fmt.Println("Telegram bot running (owner-only). Press Ctrl+C to stop.")
	return bot.Run(context.Background())
}

// StartMonitor starts the monitor service (health ticker + auto-restart).
// Restart is done by re-executing this binary (`sopr run --tunnel <name>`).
func StartMonitor(ctx context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	self, _ := os.Executable()
	m := monitor.New(30 * time.Second)
	m.HistoryFile = cfg.DataDir + "/alerts.log"
	if cfg.Telegram.Enabled && cfg.Telegram.Token != "" {
		bot := telegram.New(cfg.Telegram.Token, cfg.Telegram.OwnerID)
		m.Alert = func(t config.Tunnel, up bool, msg string) {
			bot.Alert(ctx, t, up, msg)
		}
	}
	m.Restart = func(_ context.Context, t config.Tunnel) error {
		cmd := exec.CommandContext(ctx, self, "run", "--tunnel", t.Name, "--config", cfgPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Start()
	}
	m.Run(ctx, cfg.Tunnels)
	return nil
}
