// Package backup: zip backup / restore of the GOLDEN SOPR config (and any
// metrics snapshot file next to it). Stdlib only. Based on BackPack by
// Amin Mohammadi (AminMGMT) https://github.com/AminMGMT/BackPack - AGPL-3.0.
package backup

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/soprpack/soprpack/internal/config"
)

// Backup creates a zip at dst containing config.json (+ metrics.json if it
// exists next to the config). dst defaults to soprpack-backup-<date>.zip.
func Backup(configPath, dst string) (string, error) {
	if configPath == "" {
		configPath = config.DefaultPath()
	}
	if _, err := os.Stat(configPath); err != nil {
		return "", fmt.Errorf("config not found at %s: %w", configPath, err)
	}
	if dst == "" {
		dst = fmt.Sprintf("soprpack-backup-%s.zip", time.Now().Format("20060102-150405"))
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	add := func(path, name string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	}
	if err := add(configPath, "config.json"); err != nil {
		return "", err
	}
	// Optional extras, best-effort.
	for _, extra := range []string{"metrics.json", "alerts.json"} {
		p := filepath.Join(filepath.Dir(configPath), extra)
		if _, err := os.Stat(p); err == nil {
			_ = add(p, extra)
		}
	}
	// Manifest so a restore can sanity-check the archive.
	mw, err := zw.Create("MANIFEST.txt")
	if err == nil {
		fmt.Fprintf(mw, "GOLDEN SOPR backup\ncreated: %s\nconfig: %s\n",
			time.Now().Format(time.RFC3339), configPath)
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return dst, nil
}

// Restore extracts a backup zip into dir, validates the contained
// config.json, and returns its path. It refuses paths escaping dir.
func Restore(zipPath, dir string) (string, error) {
	if dir == "" {
		dir = filepath.Dir(config.DefaultPath())
	}
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()
	var cfgPath string
	for _, f := range r.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			return "", fmt.Errorf("unsafe entry in backup: %s", f.Name)
		}
		dst := filepath.Join(dir, filepath.Base(f.Name))
		if f.Name == "config.json" {
			cfgPath = dst
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return "", err
		}
	}
	if cfgPath == "" {
		return "", fmt.Errorf("backup contains no config.json")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return "", fmt.Errorf("restored config is invalid: %w", err)
	}
	for i := range cfg.Tunnels {
		if err := cfg.Tunnels[i].Validate(); err != nil {
			return "", fmt.Errorf("tunnel %q invalid: %w", cfg.Tunnels[i].Name, err)
		}
	}
	return cfgPath, nil
}
