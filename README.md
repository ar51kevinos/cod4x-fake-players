# CoD4x Fake Players

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)

Protocol-aware **connection load tester** for **your own** CoD4x game server.

Simulates multiple clients performing the real OOB handshake (`getchallenge` → `challengeResponse` → `connect` with userinfo) so you can test how your server handles concurrent joins, rejects, and timeouts.

> **Important**  
> Use this **only** against servers **you own** (local / private lab).  
> Do **not** use it against public servers.

---

## Why this exists

CoD4x servers implement connection logic and protections such as:

- Challenge/response before `connect`
- Protocol / `xver` checks
- **Fake-Player-DoS protection**: incomplete connections from the **same IP** can block further joins from that IP

This tool helps you **observe and stress those behaviours on your lab server**.

---

## Features

- Real CoD4x-style OOB handshake
- Configurable client count, stagger, session time
- `protocol` + `xver` fields in userinfo
- JSON config + CLI overrides
- Optional `proxy.txt` list (for **controlled** lab forwarders / documentation)
- File logging + summary stats
- Safety lock: refuses non-private hosts by default

---

## Requirements

- Python **3.8+**
- A CoD4x server you control (example: `127.0.0.1:28969`)

No third-party packages.

---

## Quick start

```bash
git clone https://github.com/ar51kevinos/cod4x-fake-players.git
cd cod4x-fake-players

cp config.example.json config.json
# edit server.host / server.port if needed

python fake_players.py
```

Example:

```bash
python fake_players.py --host 127.0.0.1 --port 28969 -n 3 --stagger 2
```

---

## Configuration

See `config.example.json`.

| Key | Meaning | Default |
|-----|---------|---------|
| `server.host` | Target IP | `127.0.0.1` |
| `server.port` | Target port | `28969` |
| `clients.count` | Number of fake clients | `5` |
| `clients.stagger_seconds` | Delay between starts | `1.5` |
| `clients.session_time_seconds` | How long each client listens | `25` |
| `clients.protocol` | userinfo `protocol` | `6` |
| `clients.xver` | userinfo `xver` | `21` |
| `proxy.enabled` | Load `proxy.txt` | `false` |
| `safety.allow_only_private_hosts` | Block public targets | `true` |

---

## About proxies / different IPs

CoD4x can refuse several **incomplete** joins from one IP.

To test multi-IP behaviour in a lab you can:

1. Use **multiple local addresses** / network namespaces / VMs (best)
2. Use a **UDP forwarder you control** that presents different source IPs to your server
3. List such endpoints in `proxy.txt` for bookkeeping

**Important:** a normal HTTP proxy or SOCKS proxy **without UDP support** cannot carry CoD4 game packets.  
This project does **not** turn random public proxies into working game clients.

---

## CLI

```bash
python fake_players.py -h

python fake_players.py -n 5 --stagger 2 --time 30
python fake_players.py --protocol 6 --xver 21.2
python fake_players.py --proxies          # enable proxy.txt
python fake_players.py --no-proxies
```

---

## Interpreting results

Watch **both** this tool’s output and your CoD4x server console.

| Observation | Likely meaning |
|-------------|----------------|
| `challengeResponse ...` | Challenge step OK |
| `Going from CS_FREE to CS_CONNECTED` (server log) | Server accepted the client slot briefly |
| `uncompleted connection` / Fake-Player-DoS | Same-IP incomplete connect protection |
| `No or bad challenge` | Challenge mismatch |
| Protocol / subversion error | Adjust `protocol` / `xver` |
| Timeout after connect | Server dropped an incomplete client (expected without full netchan) |

A full in-game bot needs continuous netchan / usercmd traffic. This tool focuses on the **join handshake and server policy**, not playing the match.

---

## Project layout

```text
cod4x-fake-players/
├── fake_players.py
├── config.example.json
├── proxy.txt.example
├── requirements.txt
├── .gitignore
├── README.md
└── LICENSE
```

---

## Disclaimer

This software is a **lab testing utility** for administrators of their own CoD4x servers.

Misuse against systems you do not own may violate terms of service and applicable law.  
The authors assume no liability for misuse.

---

## License

MIT – see [LICENSE](LICENSE).
