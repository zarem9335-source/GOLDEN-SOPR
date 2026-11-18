// Package cmd: GOLDEN SOPR CLI commands. Stdlib only for the command layer;
// the tunnel engine lives in internal/core. Based on BackPack by Amin
// Mohammadi (AminMGMT) https://github.com/AminMGMT/BackPack - AGPL-3.0.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soprpack/soprpack/internal/config"
	"github.com/soprpack/soprpack/internal/core"
)

// callEngineMethod invokes e.RunServer(ctx) or e.RunClient(ctx) directly.
func callEngineMethod(ctx context.Context, e *core.Engine, name string) error {
	if name == "RunServer" {
		return e.RunServer(ctx)
	}
	return e.RunClient(ctx)
}

// LoadTunnel loads the config and returns the named tunnel (or the first
// enabled one when name is empty).
func LoadTunnel(cfgPath, name string) (*config.Config, *config.Tunnel, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if name != "" {
		t := cfg.Find(name)
		if t == nil {
			return nil, nil, fmt.Errorf("tunnel %q not found", name)
		}
		return cfg, t, nil
	}
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Enabled {
			return cfg, &cfg.Tunnels[i], nil
		}
	}
	if len(cfg.Tunnels) > 0 {
		return cfg, &cfg.Tunnels[0], nil
	}
	return nil, nil, fmt.Errorf("no tunnels configured — run `sopr setup-iran` first")
}

// RunTunnel runs one tunnel until SIGINT/SIGTERM. On SIGHUP it re-reads
// the config and restarts the engine with the (possibly) updated tunnel.
func RunTunnel(cfgPath, name string) error {
	for {
		cfg, t, err := LoadTunnel(cfgPath, name)
		if err != nil {
			return err
		}
		_ = cfg
		if err := t.Validate(); err != nil {
			return fmt.Errorf("invalid tunnel %q: %w", t.Name, err)
		}
		method := "RunClient"
		if t.Role == config.RoleIran {
			method = "RunServer"
		}
		fmt.Printf("GOLDEN SOPR: starting tunnel %q role=%s transport=%s port=%d\n",
			t.Name, t.Role, t.Transport, t.TunnelPort)
		if t.Preset == config.PresetGaming || t.Transport == "wg-gaming" {
			fmt.Println("Gaming mode: wg-gaming, keepalive 5s, MTU 1280, DSCP EF, UDP duplication + FEC on game ports")
		}

		ctx, cancel := context.WithCancel(context.Background())
		sig := make(chan os.Signal, 3)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		engine := core.New(*t)
		engine.OnStatus = func(up bool, msg string) {
			st := "DOWN"
			if up {
				st = "UP"
			}
			fmt.Printf("[%s] %s: %s\n", t.Name, st, msg)
		}
		done := make(chan error, 1)
		go func() { done <- callEngineMethod(ctx, engine, method) }()

		reload := false
		var runErr error
		select {
		case runErr = <-done:
		case s := <-sig:
			if s == syscall.SIGHUP {
				fmt.Println("SIGHUP: reloading config…")
				reload = true
			} else {
				fmt.Println("Shutting down…")
			}
		}
		cancel()
		engine.Stop()
		// Drain the engine goroutine (bounded wait so a stuck engine
		// cannot hang shutdown forever).
		select {
		case e := <-done:
			if runErr == nil {
				runErr = e
			}
		case <-time.After(5 * time.Second):
			fmt.Println("Engine did not stop in 5s, continuing shutdown.")
		}
		signal.Stop(sig)
		if reload {
			name = t.Name
			continue
		}
		return runErr
	}
}
