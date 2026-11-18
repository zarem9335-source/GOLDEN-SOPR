// Command sopr: GOLDEN SOPR tunnel engine CLI.
// Usage: sopr [--config path] <command>
// Commands: setup-iran, setup-kharej, manage, run, link, health,
// linktest, optimize, backup, restore, web, telegram, monitor, version.
// With no command, the interactive menu opens.
// Based on BackPack by Amin Mohammadi (AminMGMT)
// https://github.com/AminMGMT/BackPack - AGPL-3.0, own branding GOLDEN SOPR.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/soprpack/soprpack/cmd"
	"github.com/soprpack/soprpack/internal/backup"
	"github.com/soprpack/soprpack/internal/config"
)

const version = "v1.0.0" // golden-sopr v1.0.0

func main() {
	cfgPath := flag.String("config", "", "config file path (default: "+config.DefaultPath()+")")
	tunnel := flag.String("tunnel", "", "tunnel name")
	role := flag.String("role", "", "role filter (iran/kharej, informational)")
	flag.Parse()
	_ = role
	if *cfgPath == "" {
		*cfgPath = config.DefaultPath()
	}
	args := flag.Args()
	// Also accept flags after the subcommand, e.g. `golden-sopr run --config x --tunnel y`.
	for i := 1; i < len(args); i++ {
		if (args[i] == "--config" || args[i] == "--tunnel") && i+1 < len(args) {
			if args[i] == "--config" {
				*cfgPath = args[i+1]
			} else {
				*tunnel = args[i+1]
			}
			i++
		}
	}
	if len(args) == 0 {
		if err := cmd.RunMenu(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}
	var err error
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println("golden-sopr", version, "(GOLDEN SOPR — Based on BackPack by Amin Mohammadi (AminMGMT))")
	case "setup-iran":
		err = cmd.SetupIran(*cfgPath)
	case "setup-kharej":
		err = cmd.SetupKharej(*cfgPath)
	case "manage":
		err = cmd.Manage(*cfgPath)
	case "run":
		err = cmd.RunTunnel(*cfgPath, *tunnel)
	case "link":
		// sopr link apply <sopr://...>
		if len(args) >= 3 && args[1] == "apply" {
			t, e := cmd.ApplyLink(args[2], *cfgPath)
			if e != nil {
				err = e
				break
			}
			cmd.PrintTunnelSummary(t)
		} else {
			fmt.Fprintln(os.Stderr, "usage: sopr link apply <sopr://...>")
			os.Exit(2)
		}
	case "health":
		_, t, e := cmd.LoadTunnel(*cfgPath, *tunnel)
		if e != nil {
			err = e
			break
		}
		if !cmd.HealthCheck(t) {
			os.Exit(3)
		}
	case "linktest":
		err = cmd.LinkTestMenu(*cfgPath)
	case "optimize":
		err = cmd.OptimizeMenu()
	case "backup":
		dst := ""
		if len(args) >= 2 {
			dst = args[1]
		}
		var p string
		p, err = backup.Backup(*cfgPath, dst)
		if err == nil {
			fmt.Println("Backup written to:", p)
		}
	case "restore":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: sopr restore <backup.zip>")
			os.Exit(2)
		}
		var p string
		p, err = backup.Restore(args[1], "")
		if err == nil {
			fmt.Println("Restored config to:", p)
		}
	case "web":
		err = cmd.WebPanelMenu(*cfgPath)
	case "telegram":
		err = cmd.TelegramMenu(*cfgPath)
	case "monitor":
		err = cmd.StartMonitor(context.Background(), *cfgPath)
	case "help", "-h", "--help":
		fmt.Println("\033[38;5;220m✨ golden-sopr — GOLDEN SOPR tunnel engine " + version + "\033[0m")
		fmt.Println("Commands: setup-iran, setup-kharej, manage, run [--tunnel NAME],")
		fmt.Println("  link apply <sopr://...>, health [--tunnel NAME], linktest,")
		fmt.Println("  optimize, backup [file], restore <file>, web, telegram, monitor, version")
		fmt.Println("No command opens the interactive menu. Web panel default: 127.0.0.1:2097 (gold theme)")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q — run `sopr help`\n", args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
