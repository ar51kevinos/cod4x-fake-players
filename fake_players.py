#!/usr/bin/env python3
"""
CoD4x Fake Players
==================
Protocol-aware connection load tester for YOUR OWN CoD4x server.

Implements the real OOB handshake from the CoD4x server source:
  1. getchallenge [clientChallenge]
  2. parse challengeResponse
  3. connect with userinfo (challenge, qport, protocol, name, xver, ...)
  4. listen for error / print / further replies
  5. report stats

LOCAL / PRIVATE LAB USE ONLY.
Do not point this tool at servers you do not own.

CoD4x includes "Fake-Player-DoS protection": multiple incomplete connections
from the same IP are rejected. Use a small client count, stagger delays,
or different source IPs (local interfaces / controlled forwarders) when testing.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "config.json"
EXAMPLE_CONFIG = BASE_DIR / "config.example.json"

# ---------------------------------------------------------------------------
# Logging / stats
# ---------------------------------------------------------------------------

log_lock = threading.Lock()
log_fp = None
running = True


def setup_log(path: str):
    global log_fp
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    log_fp = open(p, "a", encoding="utf-8")
    log(f"=== Fake Players started {datetime.now().isoformat()} ===")


def log(msg: str, console: bool = True):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    with log_lock:
        if log_fp:
            log_fp.write(line + "\n")
            log_fp.flush()
    if console:
        print(line)


@dataclass
class Stats:
    challenges_ok: int = 0
    connects_sent: int = 0
    errors: int = 0
    positive: int = 0
    timeouts: int = 0
    dos_protection_hits: int = 0


stats = Stats()
stats_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Config / proxies
# ---------------------------------------------------------------------------

def load_config(path: Path) -> dict:
    if not path.exists():
        if EXAMPLE_CONFIG.exists():
            print(f"[!] {path.name} missing – copying from config.example.json")
            path.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            print(f"[!] No config at {path}")
            sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_proxies(filename: str) -> List[Tuple[str, int]]:
    path = BASE_DIR / filename
    out: List[Tuple[str, int]] = []
    if not path.is_file():
        return out
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            log(f"proxy.txt line {i} ignored: {line}")
            continue
        try:
            host, port_s = line.rsplit(":", 1)
            out.append((host.strip(), int(port_s)))
        except ValueError:
            log(f"proxy.txt line {i} bad port: {line}")
    return out


def is_allowed_host(host: str, cfg: dict) -> bool:
    safety = cfg.get("safety", {})
    if not safety.get("allow_only_private_hosts", True):
        return True
    allowed = set(safety.get("allowed_hosts") or [])
    if host in allowed:
        return True
    if host.startswith(("192.168.", "10.", "127.")):
        return True
    # 172.16.0.0 – 172.31.255.255
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def oob(s: str) -> bytes:
    return b"\xff\xff\xff\xff" + s.encode("latin-1", errors="replace")


def parse_oob(data: bytes) -> str:
    if data.startswith(b"\xff\xff\xff\xff"):
        return data[4:].decode("latin-1", errors="ignore")
    return data.decode("latin-1", errors="ignore")


def build_userinfo(name: str, challenge: str, qport: int, protocol: int, xver: str) -> str:
    fields = {
        "challenge": str(challenge),
        "qport": str(qport),
        "protocol": str(protocol),
        "name": name,
        "rate": "25000",
        "snaps": "20",
        "cl_voice": "0",
        "cl_anonymous": "0",
        "color": "7",
        "xver": xver,
        "password": "",
        "clanAbbrev": "",
    }
    return "".join(f"\\{k}\\{v}" for k, v in fields.items())


# ---------------------------------------------------------------------------
# Fake client
# ---------------------------------------------------------------------------

class FakeClient:
    def __init__(
        self,
        index: int,
        host: str,
        port: int,
        protocol: int,
        xver: str,
        session_time: float,
        name_prefix: str,
        proxy: Optional[Tuple[str, int]] = None,
        console_log: bool = True,
    ):
        self.index = index
        self.host = host
        self.port = port
        self.protocol = protocol
        self.xver = xver
        self.session_time = session_time
        self.proxy = proxy
        self.console_log = console_log

        self.name = f"{name_prefix}_{index:02d}_{random.randint(100, 999)}"
        self.qport = random.randint(1000, 60000)
        self.client_challenge = random.randint(1, 0x7FFFFFFF)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(2.0)
        self.local_port = self.sock.getsockname()[1]

    def _log(self, msg: str):
        log(msg, console=self.console_log)

    def send_raw(self, payload: str):
        """
        Send OOB packet to the game server.
        Proxy support here is informational / reserved for controlled UDP forwarders.
        Standard SOCKS HTTP proxies cannot carry CoD4 UDP; use local multi-IP or
        a real UDP forwarder if you need different source addresses.
        """
        target = (self.host, self.port)
        self.sock.sendto(oob(payload), target)

    def recv(self, timeout: float = 2.0) -> Optional[str]:
        self.sock.settimeout(timeout)
        try:
            data, _ = self.sock.recvfrom(8192)
            return parse_oob(data)
        except (socket.timeout, OSError):
            return None

    def run(self):
        proxy_s = f"{self.proxy[0]}:{self.proxy[1]}" if self.proxy else "-"
        tag = (
            f"#{self.index:02d} [{self.name}] "
            f"qport={self.qport} lport={self.local_port} proxy={proxy_s}"
        )

        try:
            # 1) getchallenge
            self.send_raw(f"getchallenge {self.client_challenge}")
            self._log(f"{tag} → getchallenge {self.client_challenge}")

            reply = self.recv(3.0)
            if not reply:
                self._log(f"{tag} ← timeout (no challengeResponse)")
                with stats_lock:
                    stats.timeouts += 1
                return

            self._log(f"{tag} ← {reply[:140]}")

            server_challenge = None
            if reply.startswith("challengeResponse"):
                parts = reply.split()
                if len(parts) >= 2:
                    server_challenge = parts[1]
                with stats_lock:
                    stats.challenges_ok += 1
            elif reply.lower().startswith(("error", "print")):
                with stats_lock:
                    stats.errors += 1
                return
            else:
                parts = reply.split()
                for p in parts:
                    if p.lstrip("-").isdigit():
                        server_challenge = p
                        break

            if not server_challenge:
                self._log(f"{tag} could not parse challenge")
                with stats_lock:
                    stats.errors += 1
                return

            # 2) connect
            userinfo = build_userinfo(
                self.name, server_challenge, self.qport, self.protocol, self.xver
            )
            self.send_raw(f'connect "{userinfo}"')
            self._log(f"{tag} → connect challenge={server_challenge}")
            with stats_lock:
                stats.connects_sent += 1

            # 3) listen
            end = time.time() + self.session_time
            got = False
            while time.time() < end and running:
                msg = self.recv(1.0)
                if msg is None:
                    continue
                got = True
                short = msg.replace("\n", " | ")[:160]
                self._log(f"{tag} ← {short}")

                low = msg.lower()
                if "uncompleted connection" in low or "fake-player" in low or "fake player" in low:
                    with stats_lock:
                        stats.dos_protection_hits += 1
                        stats.errors += 1
                    self._log(f"{tag} CoD4x Fake-Player-DoS protection triggered")
                    break
                if low.startswith("error") or "rejected" in low or "refused" in low:
                    with stats_lock:
                        stats.errors += 1
                    break
                if "disconnect" in low:
                    with stats_lock:
                        stats.errors += 1
                    break
                if not low.startswith("error"):
                    with stats_lock:
                        stats.positive += 1

            if not got:
                self._log(f"{tag} no post-connect reply (silent drop or still connecting)")
                with stats_lock:
                    stats.timeouts += 1
            else:
                self._log(f"{tag} session finished")

        except Exception as e:
            self._log(f"{tag} exception: {e}")
            with stats_lock:
                stats.errors += 1
        finally:
            try:
                self.sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="CoD4x Fake Players – local lab connection tester"
    )
    p.add_argument("-c", "--config", default=str(DEFAULT_CONFIG))
    p.add_argument("--host", help="Override server host")
    p.add_argument("--port", type=int, help="Override server port")
    p.add_argument("-n", "--count", type=int, help="Number of fake clients")
    p.add_argument("--stagger", type=float, help="Delay between clients (seconds)")
    p.add_argument("--time", type=float, help="Session time per client")
    p.add_argument("--protocol", type=int, help="userinfo protocol")
    p.add_argument("--xver", help="userinfo xver")
    p.add_argument("--proxies", action="store_true", help="Enable proxy.txt")
    p.add_argument("--no-proxies", action="store_true", help="Disable proxies")
    return p.parse_args()


def main():
    global running, log_fp

    args = parse_args()
    cfg = load_config(Path(args.config))

    # CLI overrides
    if args.host:
        cfg.setdefault("server", {})["host"] = args.host
    if args.port:
        cfg.setdefault("server", {})["port"] = args.port
    if args.count is not None:
        cfg.setdefault("clients", {})["count"] = args.count
    if args.stagger is not None:
        cfg["clients"]["stagger_seconds"] = args.stagger
    if args.time is not None:
        cfg["clients"]["session_time_seconds"] = args.time
    if args.protocol is not None:
        cfg["clients"]["protocol"] = args.protocol
    if args.xver:
        cfg["clients"]["xver"] = args.xver
    if args.proxies:
        cfg.setdefault("proxy", {})["enabled"] = True
    if args.no_proxies:
        cfg.setdefault("proxy", {})["enabled"] = False

    host = cfg["server"]["host"]
    port = int(cfg["server"]["port"])
    clients_cfg = cfg.get("clients", {})
    count = int(clients_cfg.get("count", 5))
    stagger = float(clients_cfg.get("stagger_seconds", 1.5))
    session_time = float(clients_cfg.get("session_time_seconds", 25))
    protocol = int(clients_cfg.get("protocol", 6))
    xver = str(clients_cfg.get("xver", "21"))
    name_prefix = str(clients_cfg.get("name_prefix", "LoadBot"))
    console = cfg.get("logging", {}).get("console", True)

    if not is_allowed_host(host, cfg):
        print("[!] Host not allowed. This tool is restricted to local/private lab targets.")
        print("    Set server.host to 127.0.0.1 (or adjust safety.allowed_hosts for your LAN).")
        sys.exit(1)

    setup_log(cfg.get("logging", {}).get("file", "logs/fake_players.log"))

    print("=" * 70)
    print("  CoD4x Fake Players – protocol handshake load test")
    print("  FOR YOUR OWN SERVER ONLY")
    print("=" * 70)
    print(f"  Target   : {host}:{port}")
    print(f"  Clients  : {count}")
    print(f"  Protocol : {protocol} | xver : {xver}")
    print(f"  Stagger  : {stagger}s | session : {session_time}s")
    print("=" * 70)
    print()
    print("Note: CoD4x rejects parallel incomplete connects from the same IP.")
    print("      Use small -n and non-zero stagger. Different source IPs help.")
    print()

    proxies: List[Tuple[str, int]] = []
    if cfg.get("proxy", {}).get("enabled"):
        proxies = load_proxies(cfg["proxy"].get("file", "proxy.txt"))
        if proxies:
            log(f"Loaded {len(proxies)} proxy/forwarder entr(y/ies) from file")
            log("Reminder: HTTP/SOCKS without UDP associate will not carry game traffic.")
        else:
            log("proxy enabled but list empty – continuing without")

    def stop(sig=None, frame=None):
        global running
        running = False
        print("\n[*] Stopping...")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    threads: List[threading.Thread] = []
    for i in range(1, count + 1):
        if not running:
            break
        proxy = proxies[(i - 1) % len(proxies)] if proxies else None
        client = FakeClient(
            i, host, port, protocol, xver, session_time, name_prefix, proxy, console
        )
        t = threading.Thread(target=client.run, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(stagger)

    for t in threads:
        t.join()

    print()
    print("=" * 70)
    print("  SUMMARY")
    print(f"  Challenges OK      : {stats.challenges_ok}")
    print(f"  Connects sent      : {stats.connects_sent}")
    print(f"  Errors / refused   : {stats.errors}")
    print(f"  DoS-protection hits: {stats.dos_protection_hits}")
    print(f"  Positive replies   : {stats.positive}")
    print(f"  Timeouts           : {stats.timeouts}")
    print("=" * 70)
    log("Run finished.")
    if log_fp:
        log_fp.close()


if __name__ == "__main__":
    main()
