// Package optimize: GOLDEN SOPR system tuning (BBR, MSS clamp, gaming sysctls).
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack — AGPL-3.0, own branding GOLDEN SOPR.
//
// Everything here is best-effort: each sysctl is applied individually
// and reported as applied or skipped, so one missing key never fails
// the whole tune. All of it needs root; without root every call returns
// the skipped list with a clear reason.
package optimize

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CheckRoot reports whether we run as root (needed for sysctl tuning).
func CheckRoot() bool { return os.Geteuid() == 0 }

// Result is the per-key outcome of a tuning pass.
type Result struct {
	Applied []string          // keys successfully set
	Skipped map[string]string // key -> reason it was not applied
}

// sysctlSet applies one key=value via the sysctl binary.
func sysctlSet(key, value string) error {
	cmd := exec.Command("sysctl", "-w", key+"="+value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func applyAll(keys map[string]string) Result {
	res := Result{Skipped: map[string]string{}}
	if !CheckRoot() {
		for k := range keys {
			res.Skipped[k] = "needs root"
		}
		return res
	}
	for k, v := range keys {
		if err := sysctlSet(k, v); err != nil {
			res.Skipped[k] = err.Error()
		} else {
			res.Applied = append(res.Applied, k+"="+v)
		}
	}
	return res
}

// ApplyBBR enables BBR congestion control + fq, TCP fast open and
// larger socket buffers — the single biggest throughput lever on a
// lossy Iran<->abroad path. Returns per-key results, never an error
// for a single failed key.
func ApplyBBR() Result {
	return applyAll(map[string]string{
		"net.ipv4.tcp_congestion_control": "bbr",
		"net.core.default_qdisc":          "fq",
		"net.ipv4.tcp_fastopen":           "3",
		"net.core.rmem_max":               "67108864",
		"net.core.wmem_max":               "67108864",
		"net.ipv4.tcp_rmem":               "4096 87380 67108864",
		"net.ipv4.tcp_wmem":               "4096 65536 67108864",
		"net.core.netdev_max_backlog":     "16384",
	})
}

// MSSClamp returns the MSS to clamp to for a given path MTU:
// MSS = MTU - 40 (IPv6 header + TCP header). Floor 576.
func MSSClamp(mtu int) int {
	mss := mtu - 40
	if mss < 576 {
		return 576
	}
	return mss
}

// GamingMSSClamp is the MSS for the wg-gaming default MTU 1280.
func GamingMSSClamp() int { return MSSClamp(1280) } // 1240

// GamingSysctl applies the low-latency gaming sysctls: low-latency TCP,
// small buffers for latency over throughput, busy polling where the
// kernel supports it. Returns per-key results.
func GamingSysctl() Result {
	return applyAll(map[string]string{
		"net.ipv4.tcp_low_latency":           "1",
		"net.core.rmem_max":                  "16777216",
		"net.core.wmem_max":                  "16777216",
		"net.ipv4.tcp_rmem":                  "4096 87380 16777216",
		"net.ipv4.tcp_wmem":                  "4096 16384 16777216",
		"net.core.netdev_budget":             "600",
		"net.ipv4.tcp_slow_start_after_idle": "0",
		"net.ipv4.tcp_no_metrics_save":       "1",
	})
}

// CheckBBR reports whether BBR is currently the active congestion control.
func CheckBBR() (bool, error) {
	out, err := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output()
	if err != nil {
		return false, fmt.Errorf("sysctl read: %w", err)
	}
	return strings.TrimSpace(string(out)) == "bbr", nil
}

// Current returns the current value of one sysctl key.
func Current(key string) (string, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
