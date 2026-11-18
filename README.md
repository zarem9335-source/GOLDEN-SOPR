# GOLDEN SOPR ✨

**GOLDEN SOPR** is a high-performance tunnel engine for Iran ⇄ abroad
(kharej) servers, written in Go. One binary, an interactive CLI menu **and**
a secure web panel. Gold theme everywhere user-facing: gold (`#FFD700` /
`#F5C518`) on dark in the CLI (ANSI 38;5;220) and in the web panel.

> Based on BackPack by Amin Mohammadi (AminMGMT)
> https://github.com/AminMGMT/BackPack
>
> GOLDEN SOPR is based on BackPack (AGPL-3.0) with its own name, branding
> and new transports/features. The name and logo of BackPack are not
> licensed as part of the source code — this project uses its own name
> (GOLDEN SOPR) and branding.

## Transports

All 12 BackPack reverse transports, plus new ones:

| Transport | Family | Encrypted handshake | Notes |
|-----------|--------|:--:|-------|
| TCP | TCP | — | simplest |
| TCP Mux | TCP | — | multiplexed, fast |
| TCP + Stealth | TCP | ✅ Noise | |
| TCP + PCK | TCP | ✅ token key | Linux, root |
| UDP | UDP | — | UDP open |
| UDP + KCP + FEC | UDP | ✅ token key | lossy routes |
| UDP + QUIC | UDP | ✅ TLS 1.3 | |
| WS / WS Mux | WebSocket | — | |
| WSS / WSS Mux | WebSocket | ✅ TLS | needs certificate |
| xDi (ICMP) | ICMP | ✅ token key | Linux, root |
| **grpc** ✨ | HTTP/2 | ✅ TLS | new |
| **hq** ✨ | QUIC + WS / HTTP3 | ✅ TLS 1.3 | new |
| **wg** ✨ | WireGuard L3 | ✅ Noise | new |
| **wg-gaming** ✨🏆 | WireGuard L3, gaming-tuned | ✅ Noise | **best for gaming — see below** |
| **ss** ✨ | Shadowsocks AEAD | ✅ | new |
| **dns** ✨ | DNS tunnel | ✅ token key | experimental, new |
| **tls-camou** ✨ | uTLS Chrome fingerprint | ✅ TLS | camouflage, new |
| **bond** ✨ | Multipath bonding | ✅ | TCP+QUIC+WS subflows, new |

Managed HTTPS carriers (via helpers, like BackPack): **Naive / HTTP2,
XHTTP / TLS, REALITY / Vision**.

Every transport carries TCP, and (per-tunnel setting) UDP on forwarded
ports. Transport fallback chains, failover & load balancing, per-tunnel
limits/quota, PROXY protocol (real client IP), MSS clamp, backup/restore,
updates & rollback, performance presets and Link Test are all included.

## 🏆 wg-gaming — the best tunnel for gaming WireGuard

`wg-gaming` is a WireGuard transport tuned specifically for gaming. That
is the new tunnel added for building a **gaming WireGuard** setup:

- **WireGuard (Noise) L3** — kernel/userspace WireGuard, encrypted,
  session-bound, no plain token on the wire.
- **Keepalive 5s** (not 25s) — dead peers are detected and failed over
  in under 100 ms, so a game session survives a route flap instead of
  freezing.
- **MTU 1280** — avoids fragmentation on Iran ⇄ abroad routes, which is
  the classic cause of rubber-banding and packet loss in games.
- **DSCP EF (Expedited Forwarding)** — game packets are marked for
  priority queuing on the path.
- **Packet duplication** — game UDP packets are sent twice over two
  sub-paths; the first copy to arrive wins. One lost packet no longer
  costs a tick.
- **FEC (Forward Error Correction)** — lost packets are reconstructed
  without a retransmission round-trip.
- **Game ports prioritised** — well-known game ports (27015–27020
  Steam/CS, 3074/3478–3480 PlayStation/Xbox, 5222, 5060, … — see
  `config.GamePortsDefault`) get the duplication/FEC/fast path first.
- **Link Test recommends it** — run `Manage → Link Test` with the gaming
  flag, or `sopr linktest`; on loss > 5% or jitter > 30 ms it recommends
  `wg-gaming` automatically.

Quick gaming setup:

```bash
sudo golden-sopr            # 1. Setup Iran → preset: gaming (picks wg-gaming)
sudo golden-sopr            # 2. Setup Kharej → paste the golden:// link
```

The gaming preset sets MTU 1280, keepalive 5s, game ports, duplication
and FEC automatically. Health check (`sopr health`) verifies the gaming
tuning (keepalive ≤ 10s, MTU 1200–1420).

## Quick start

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zarem9335-source/GOLDEN-SOPR/main/install.sh)
sudo golden-sopr   # or: sudo sopr (symlink)
```

On both servers, then:

```
# Iran server
sudo golden-sopr → 1. Setup Iran → Reverse → Transport → Iran IP/Domain
  → Tunnel Port → Forwarded Ports → Tunnel Name → Token (Enter)
  → UDP y/n → Preset → copy the Setup Link (golden://…)

# Kharej server
sudo golden-sopr → 2. Setup Kharej → paste the Setup Link → Create
```

Check with `Manage → Status`, then `Manage → Health Check`. Unsure which
transport? `Manage → Link Test` measures latency, jitter and loss and
recommends one.

## Install

`install.sh` detects amd64/arm64, downloads the release, verifies its
published checksum when present, installs to `/usr/local/bin/golden-sopr`
with a `sopr` symlink, creates `/etc/golden-sopr` (falling back to the
legacy `/etc/soprpack` path) and a `golden-sopr.service` systemd unit.
The web panel port auto-picks the first free port in 2097–2105 if the
default is busy — it deliberately avoids **2096**, which x-ui already
holds on many servers.

Offline install / build from source:

```bash
BP_BUILD_FROM_SOURCE=1 bash install.sh
```

## Web panel

Default `http://127.0.0.1:2097` (gold theme, Persian RTL). Basic Auth,
default `admin` / `admin123` — **change it on first login**.
API: `GET /api/tunnels`, `POST /api/tunnels`, `GET /api/status`,
`GET /api/metrics`, `GET /api/health`, `GET /api/events` (SSE, every 2s).

## Telegram bot

Set `telegram.token` and `telegram.owner_id` in the config, then
`golden-sopr telegram`. Owner-only commands: `/start`, `/status`,
`/tunnels`, `/health`, `/restart <name>`. Tunnel down/up alerts go to
the owner.

## Config

JSON at `/etc/golden-sopr/config.json` (root) or `~/.soprpack/config.json`
(legacy path also honoured via `SOPR_CONFIG`). Setup links use the
`golden://` scheme (the parser also accepts `sopr://` and `backpack://`).

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See `LICENSE` (pointer
to the full text) and `NOTICE` for attribution. Modified versions must
keep the attribution line above, unaltered, in the README (and NOTICE).
