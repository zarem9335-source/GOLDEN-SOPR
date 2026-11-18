package cmd

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/soprpack/soprpack/internal/config"
	"github.com/soprpack/soprpack/internal/transport"
)

// HealthCheck runs checks for one tunnel and prints PASS/FAIL/SKIP per
// check with fix hints (Persian + English). Returns true when all
// non-skipped checks pass. It never claims the tunnel carries traffic:
// the auth check is only attempted when the transport factory is present.
func HealthCheck(t *config.Tunnel) bool {
	fmt.Printf("Health check — %s (%s, %s)\n", t.Name, t.Role, t.Transport)
	ok := true
	check := func(label string, fn func() (string, error)) {
		detail, err := fn()
		switch {
		case err == nil:
			fmt.Printf("  [PASS] %s — %s\n", label, detail)
		case detail == "SKIP":
			fmt.Printf("  [SKIP] %s — %s\n", label, err.Error())
		default:
			ok = false
			fmt.Printf("  [FAIL] %s — %s\n", label, err.Error())
		}
	}

	check("Config valid / پیکربندی معتبر", func() (string, error) {
		if err := t.Validate(); err != nil {
			return "", fmt.Errorf("%v — fix: re-run setup (راه‌اندازی دوباره)", err)
		}
		return "name, token, port and transport look valid", nil
	})

	check("Iran reachable / دسترسی به ایران", func() (string, error) {
		addr := net.JoinHostPort(t.IranAddr, fmt.Sprint(t.TunnelPort))
		d := net.Dialer{Timeout: 5 * time.Second}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			return "", fmt.Errorf("%v — fix: check Iran IP/port, firewall, and that the Iran side is running (آی‌پی/پورت و فایروال ایران را بررسی کنید)", err)
		}
		_ = c.Close()
		return "TCP connect to " + addr + " succeeded", nil
	})

	check("Transport dial / اتصال ترنسپورت", func() (string, error) {
		f, err := transport.Get(t.Transport)
		if err != nil {
			return "SKIP", fmt.Errorf("transport %q not registered in this build (SKIP — transport not built yet)", t.Transport)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addr := net.JoinHostPort(t.IranAddr, fmt.Sprint(t.TunnelPort))
		c, err := f.Dial(ctx, addr, t.Token, t.Extra)
		if err != nil {
			return "", fmt.Errorf("%v — fix: token/transport mismatch or filtered route; run Link Test (توکن یا ترنسپورت ناسازگار است، Link Test بگیرید)", err)
		}
		_ = c.Close()
		return "transport dial succeeded (auth is verified by the engine handshake)", nil
	})

	check("Forwarded ports sane / پورت‌های فوروارد", func() (string, error) {
		if len(t.Ports) == 0 {
			return "", fmt.Errorf("no forwarded ports — fix: add at least one port mapping (پورت فوروارد اضافه کنید)")
		}
		return fmt.Sprintf("%d mapping(s): %v", len(t.Ports), t.Ports), nil
	})

	if t.Transport == "wg-gaming" {
		check("Gaming tuning / تنظیمات گیمینگ", func() (string, error) {
			if t.KeepaliveSec == 0 || t.KeepaliveSec > 10 {
				return "", fmt.Errorf("keepalive should be 5s for gaming (keepalive را ۵ ثانیه بگذارید)")
			}
			if t.MTU != 0 && (t.MTU < 1200 || t.MTU > 1420) {
				return "", fmt.Errorf("MTU %d is outside the gaming range 1200–1420", t.MTU)
			}
			return fmt.Sprintf("MTU %d, keepalive %ds, game ports %v", t.MTU, t.KeepaliveSec, t.GamePorts), nil
		})
	}

	if ok {
		fmt.Println("Result: HEALTHY ✅ — all checks passed (but run a real game/voice session to confirm traffic flows).")
	} else {
		fmt.Println("Result: UNHEALTHY ❌ — fix the FAIL items above, then re-run `sopr health`.")
	}
	return ok
}
