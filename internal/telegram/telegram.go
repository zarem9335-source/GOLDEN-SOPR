// Package telegram: owner-only Telegram bot via the Bot API (long polling,
// net/http only, no external dep). Based on BackPack by Amin Mohammadi
// (AminMGMT) https://github.com/AminMGMT/BackPack - AGPL-3.0.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/soprpack/soprpack/internal/config"
)

// Bot is a minimal Telegram bot. OnCommand, if set, handles a command and
// returns the reply text; the built-in commands run when it is nil.
type Bot struct {
	Token   string
	OwnerID int64
	// Tunnels is called to list current tunnels for /status and /tunnels.
	Tunnels  func() []config.Tunnel
	IsUp     func(name string) bool
	OnAction func(ctx context.Context, action, arg string) (string, error) // e.g. ("restart", name)

	client *http.Client
	api    string
	offset int64
}

func New(token string, ownerID int64) *Bot {
	return &Bot{Token: token, OwnerID: ownerID,
		client: &http.Client{Timeout: 35 * time.Second},
		api:    "https://api.telegram.org/bot" + token}
}

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Text string `json:"text"`
	} `json:"message"`
}

func (b *Bot) apiCall(ctx context.Context, method string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		j, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.api+"/"+method, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// SendMessage sends text to a chat (owner only in practice).
func (b *Bot) SendMessage(ctx context.Context, chatID int64, text string) error {
	_, err := b.apiCall(ctx, "sendMessage", map[string]any{
		"chat_id": chatID, "text": text,
	})
	return err
}

// Alert notifies the owner that a tunnel went down/up.
func (b *Bot) Alert(ctx context.Context, t config.Tunnel, up bool, msg string) {
	if b.OwnerID == 0 || b.Token == "" {
		return
	}
	state := "✅ UP"
	if !up {
		state = "🔴 DOWN"
	}
	_ = b.SendMessage(ctx, b.OwnerID,
		fmt.Sprintf("✨ GOLDEN SOPR %s\nTunnel: %s (%s)\n%s", state, t.Name, t.Transport, msg))
}

// Run polls getUpdates until ctx ends.
func (b *Bot) Run(ctx context.Context) error {
	if b.Token == "" {
		return fmt.Errorf("telegram token is empty")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if err := b.pollOnce(ctx); err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (b *Bot) pollOnce(ctx context.Context) error {
	u := b.api + "/getUpdates?timeout=30&offset=" + fmt.Sprint(b.offset+1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var res struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	for _, up := range res.Result {
		b.offset = up.UpdateID
		if up.Message != nil {
			b.handle(ctx, up)
		}
	}
	return nil
}

func (b *Bot) handle(ctx context.Context, up update) {
	msg := up.Message
	chatID := msg.Chat.ID
	// Owner-only: ignore everyone else (and never leak tunnel info).
	if b.OwnerID != 0 && msg.From.ID != b.OwnerID {
		_ = b.SendMessage(ctx, chatID, "⛔ This bot is private.")
		return
	}
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}
	parts := strings.Fields(text)
	cmd := strings.ToLower(parts[0])
	arg := ""
	if len(parts) > 1 {
		arg = strings.Join(parts[1:], " ")
	}
	var reply string
	if b.OnAction != nil && (cmd == "/restart" || cmd == "/start" || cmd == "/stop") {
		if r, err := b.OnAction(ctx, strings.TrimPrefix(cmd, "/"), arg); err != nil {
			reply = "❌ " + err.Error()
		} else {
			reply = r
		}
	} else {
		reply = b.builtin(cmd, arg)
	}
	_ = b.SendMessage(ctx, chatID, reply)
}

func (b *Bot) builtin(cmd, arg string) string {
	switch cmd {
	case "/start":
		return "👋 ✨ GOLDEN SOPR bot\nCommands:\n/status — tunnel status\n/tunnels — list tunnels\n/health — health check\n/restart <name> — restart a tunnel"
	case "/status", "/tunnels":
		if b.Tunnels == nil {
			return "No tunnel provider configured."
		}
		ts := b.Tunnels()
		if len(ts) == 0 {
			return "No tunnels configured yet."
		}
		var sb strings.Builder
		sb.WriteString("📡 Tunnels:\n")
		for _, t := range ts {
			st := "❓"
			if b.IsUp != nil {
				if b.IsUp(t.Name) {
					st = "✅"
				} else {
					st = "🔴"
				}
			}
			fmt.Fprintf(&sb, "%s %s — %s (%s) port %d\n", st, t.Name, t.Transport, t.Role, t.TunnelPort)
		}
		return sb.String()
	case "/health":
		if b.Tunnels == nil {
			return "No tunnels configured."
		}
		var sb strings.Builder
		for _, t := range b.Tunnels() {
			st := "unknown"
			if b.IsUp != nil {
				st = "DOWN"
				if b.IsUp(t.Name) {
					st = "UP"
				}
			}
			fmt.Fprintf(&sb, "%s: %s\n", t.Name, st)
		}
		return sb.String()
	case "/restart":
		if arg == "" {
			return "Usage: /restart <tunnel-name>"
		}
		return "Restart requested for " + arg + " — handled by the server process."
	default:
		return "Unknown command. Try /status, /tunnels, /health or /restart <name>."
	}
}

// Escape is a tiny helper for building safe bot messages.
func Escape(s string) string { return url.QueryEscape(s) }
