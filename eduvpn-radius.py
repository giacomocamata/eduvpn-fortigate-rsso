#!/usr/bin/env python3
"""
eduvpn-radius — RADIUS Accounting daemon for FortiGate RSSO

Reads /var/log/eduvpn/eduvpn.log (the output of the eduVPN correlator, e.g.
eduvpn-logger) and sends RADIUS Accounting-Start/Stop packets to a FortiGate.

FortiGate receives the packets and updates its user → IP mapping table,
used by identity-based firewall policies (RSSO).

Event handling:
  connect    → Accounting-Start (with ip4, ip6, user, profile)
  disconnect → Accounting-Stop  (with session-id for matching)
  roam       → no RADIUS action: the assigned VPN IP does not change,
               only the external source IP varies. The FortiGate
               user→VPN_IP mapping remains valid.

Recovery on restart: the JSON state file keeps the active sessions;
on restart the daemon re-sends Accounting-Start to restore them.

Usage:
  eduvpn-radius.py [/path/to/config.conf]
  Default config: /etc/eduvpn-radius/eduvpn-radius.conf
"""

import configparser
import json
import logging
import os
import re
import signal
import socket
import sys
import time
import uuid
from typing import Dict, Optional

try:
    import pyrad.packet
    from pyrad.client import Client, Timeout
    from pyrad.dictionary import Dictionary
    HAS_PYRAD = True
except ImportError:
    HAS_PYRAD = False

# --------------------------------------------------------------------------
# Default paths
# --------------------------------------------------------------------------
DEFAULT_CONFIG = "/etc/eduvpn-radius/eduvpn-radius.conf"
DEFAULT_STATE  = "/var/lib/eduvpn-radius/state.json"
DEFAULT_LOG    = "/var/log/eduvpn/eduvpn.log"
DICT_PATH      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dictionary")

# --------------------------------------------------------------------------
# Global state
# --------------------------------------------------------------------------
logger = logging.getLogger("eduvpn-radius")

# Active sessions: conn (WireGuard pubkey) → session dict
sessions: Dict[str, dict] = {}

cfg: Dict[str, str] = {}
radius_client: Optional["Client"] = None
state_path: str = DEFAULT_STATE
_shutdown = False

# --------------------------------------------------------------------------
# KV parser — handles both key=value and key="value with spaces"
# --------------------------------------------------------------------------
_KV_RE = re.compile(r'(\w+)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|(\S+))')


def parse_kv(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for m in _KV_RE.finditer(text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


# --------------------------------------------------------------------------
# Session state persistence
# --------------------------------------------------------------------------
def _load_state() -> Dict[str, dict]:
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        # Corrupted, unreadable, or otherwise unusable state file must never
        # prevent the daemon from starting — start fresh instead.
        logger.warning("Could not load state file %s, starting empty: %s", state_path, e)
        return {}
    if not isinstance(data, dict):
        logger.warning("State file %s has unexpected format, starting empty", state_path)
        return {}
    return data


def _save_state() -> None:
    tmp = state_path + ".tmp"
    try:
        state_dir = os.path.dirname(state_path)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2)
        os.replace(tmp, state_path)
    except Exception as e:
        logger.warning("Could not save state: %s", e)


# --------------------------------------------------------------------------
# RADIUS
# --------------------------------------------------------------------------
def _make_session_id() -> str:
    return uuid.uuid4().hex[:16]


def _send(status_type: int, sess: dict) -> bool:
    """
    Sends a RADIUS Accounting packet to FortiGate.
    status_type: 1 = Start, 2 = Stop
    Returns True if the packet was accepted (response received).
    """
    if radius_client is None:
        return False
    try:
        pkt = radius_client.CreateAcctPacket()
        pkt["User-Name"]        = sess["user"]
        pkt["Acct-Status-Type"] = "Start" if status_type == 1 else "Stop"
        pkt["Acct-Session-Id"]  = sess["acct_session_id"]
        pkt["NAS-Identifier"]   = cfg.get("nas_identifier", socket.gethostname())

        if sess.get("profile") and sess["profile"] != "-":
            pkt["Called-Station-Id"] = sess["profile"]

        ip4 = sess.get("ip4", "-")
        if ip4 and ip4 != "-":
            pkt["Framed-IP-Address"] = ip4

        ip6 = sess.get("ip6", "-")
        if ip6 and ip6 not in ("-", ""):
            try:
                pkt["Framed-IPv6-Address"] = ip6
            except Exception:
                # Older pyrad versions may not support ipv6addr
                pass

        radius_client.SendPacket(pkt)
        return True

    except Timeout:
        logger.warning("RADIUS timeout towards %s", cfg.get("server", "?"))
        return False
    except Exception as e:
        logger.warning("RADIUS error: %s", e)
        return False


# --------------------------------------------------------------------------
# Log event handlers
# --------------------------------------------------------------------------
def handle_connect(kv: Dict[str, str]) -> None:
    conn    = kv.get("conn", "")
    user    = kv.get("user", "-")
    ip4     = kv.get("tunnel_ip4", "-")
    ip6     = kv.get("tunnel_ip6", "-")
    profile = kv.get("profile", "-")

    if not conn or user in ("-", ""):
        return

    # If a session already exists for the same conn (rapid reconnect),
    # close the old one first.
    if conn in sessions:
        old = sessions[conn]
        _send(2, old)
        logger.info("stop(replaced) user=%s ip4=%s conn=%.12s",
                    old.get("user", "-"), old.get("ip4", "-"), conn)

    sess = {
        "user":            user,
        "ip4":             ip4,
        "ip6":             ip6,
        "profile":         profile,
        "acct_session_id": _make_session_id(),
    }
    sessions[conn] = sess

    ok = _send(1, sess)
    logger.info("start user=%s ip4=%s ip6=%s profile=%s ok=%s conn=%.12s",
                user, ip4, ip6, profile, ok, conn)
    _save_state()


def handle_disconnect(kv: Dict[str, str]) -> None:
    conn = kv.get("conn", "")
    user = kv.get("user", "-")

    if not conn:
        return

    sess = sessions.pop(conn, None)
    if sess is None:
        # Untracked session (daemon was inactive during the connection)
        logger.warning("disconnect for unknown session user=%s conn=%.12s", user, conn)
        return

    ok = _send(2, sess)
    logger.info("stop user=%s ip4=%s ip6=%s profile=%s ok=%s conn=%.12s",
                sess.get("user", "-"), sess.get("ip4", "-"), sess.get("ip6", "-"),
                sess.get("profile", "-"), ok, conn)
    _save_state()


def handle_roam(kv: Dict[str, str]) -> None:
    # The assigned VPN IP does NOT change during a WireGuard roam:
    # only the client's external source IP changes (e.g. WiFi → LTE).
    # The FortiGate user→VPN_IP mapping is still valid → no RADIUS action.
    user    = kv.get("user", "-")
    conn    = kv.get("conn", "")
    src_old = kv.get("src_ip_old", "-")
    src_new = kv.get("src_ip", "-")
    logger.debug("roam user=%s conn=%.12s %s→%s (no RADIUS action)",
                 user, conn, src_old, src_new)


def process_line(line: str) -> None:
    line = line.strip()
    if not line or "event=" not in line:
        return

    # Format: "2025-01-15T10:30:00.000+00:00 event=connect user=..."
    space = line.find(" ")
    if space < 0:
        return

    kv = parse_kv(line[space + 1:])
    event = kv.get("event")

    if event == "connect":
        handle_connect(kv)
    elif event == "disconnect":
        handle_disconnect(kv)
    elif event == "roam":
        handle_roam(kv)


# --------------------------------------------------------------------------
# Recovery on restart
# --------------------------------------------------------------------------
def recover_sessions() -> None:
    if not sessions:
        logger.info("No previous sessions to recover")
        return
    logger.info("Recovery: re-sending Accounting-Start for %d active sessions", len(sessions))
    for conn, sess in list(sessions.items()):
        ok = _send(1, sess)
        logger.info("recover start user=%s ip4=%s ok=%s conn=%.12s",
                    sess.get("user", "-"), sess.get("ip4", "-"), ok, conn)


# --------------------------------------------------------------------------
# Graceful shutdown
# --------------------------------------------------------------------------
def _handle_shutdown(signum, frame) -> None:
    global _shutdown
    logger.info("Signal %d: sending Accounting-Stop for all sessions...", signum)
    _shutdown = True
    for conn, sess in list(sessions.items()):
        _send(2, sess)
        logger.info("stop(shutdown) user=%s ip4=%s conn=%.12s",
                    sess.get("user", "-"), sess.get("ip4", "-"), conn)
    sessions.clear()
    _save_state()
    sys.exit(0)


# --------------------------------------------------------------------------
# Log follower — follows the live file with log rotation handling
# --------------------------------------------------------------------------
def follow_log(log_path: str) -> None:
    while not _shutdown:
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                f.seek(0, 2)  # start from the end of the current file
                logger.info("Following log: %s", log_path)
                current_ino = os.fstat(f.fileno()).st_ino

                while not _shutdown:
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        # Check whether the file was rotated (inode changed)
                        try:
                            if os.stat(log_path).st_ino != current_ino:
                                logger.info("Log rotated, reopening file")
                                break
                        except FileNotFoundError:
                            break
                        continue
                    process_line(line)

        except FileNotFoundError:
            logger.warning("Log file not found: %s — retrying in 10s", log_path)
            time.sleep(10)
        except Exception as e:
            logger.error("Error in log follower: %s — retrying in 5s", e)
            time.sleep(5)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def _parse_config(parser: configparser.ConfigParser, config_path: str) -> Dict[str, str]:
    """Builds the cfg dict from a loaded ConfigParser.

    A missing [radius]/[eduvpn] section or a required key is a user config
    error, not a bug — report it cleanly and exit rather than crashing with
    a raw traceback.
    """
    try:
        return {
            "server":         parser.get("radius", "server"),
            "port":           parser.get("radius", "port", fallback="1813"),
            "secret":         parser.get("radius", "secret"),
            "nas_identifier": parser.get("radius", "nas_identifier", fallback=socket.gethostname()),
            "log_path":       parser.get("eduvpn", "log_path", fallback=DEFAULT_LOG),
            "state_path":     parser.get("eduvpn", "state_path", fallback=DEFAULT_STATE),
        }
    except configparser.Error as e:
        logger.error("Invalid configuration in %s: %s", config_path, e)
        sys.exit(1)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main() -> None:
    global cfg, radius_client, sessions, state_path

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )

    if not HAS_PYRAD:
        logger.error("pyrad is not installed. Install it with: apt install python3-pyrad")
        sys.exit(1)

    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG

    parser = configparser.ConfigParser()
    try:
        read_ok = parser.read(config_path)
    except configparser.Error as e:
        logger.error("Invalid configuration syntax in %s: %s", config_path, e)
        sys.exit(1)
    if not read_ok:
        logger.error("Could not read configuration file: %s", config_path)
        sys.exit(1)

    cfg = _parse_config(parser, config_path)
    state_path = cfg["state_path"]

    if not os.path.isfile(DICT_PATH):
        logger.error("RADIUS dictionary not found: %s", DICT_PATH)
        sys.exit(1)

    try:
        d = Dictionary(DICT_PATH)
        radius_client = Client(
            server=cfg["server"],
            authport=1812,
            acctport=int(cfg["port"]),
            secret=cfg["secret"].encode(),
            dict=d,
        )
        radius_client.timeout = 5
        radius_client.retries = 2
    except Exception as e:
        logger.error("Could not initialize RADIUS client: %s", e)
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    sessions = _load_state()
    recover_sessions()

    follow_log(cfg["log_path"])


if __name__ == "__main__":
    main()
