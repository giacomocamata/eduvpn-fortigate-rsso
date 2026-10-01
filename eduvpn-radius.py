#!/usr/bin/env python3
"""
eduvpn-radius — RADIUS Accounting daemon for FortiGate RSSO

Follows /var/log/eduvpn/eduvpn.log (written by eduvpn-logger or a compatible
correlator) and sends RADIUS Accounting-Start/Stop packets to a FortiGate, whose
RSSO agent turns them into a user → IP table for identity-based policies.

Event handling:
  connect    → Accounting-Start (user, profile, tunnel IPv4/IPv6)
  disconnect → Accounting-Stop  (same Acct-Session-Id as the Start)
  roam       → nothing: the tunnel IP does not change, only the public source IP
  every hour → Accounting Interim-Update for every open session, or FortiGate
               drops the user after its rsso-context-timeout (default 8 h)

Restarts: the state file keeps the active sessions AND the position reached in
the log. On start the daemon first replays what was logged while it was down,
then re-sends Accounting-Start for every session still open. On SIGTERM it sends
Accounting-Stop for every session (no stale user → IP mapping while it is down)
but keeps them in the state file for the next start.

Usage:
  eduvpn-radius.py [config]              run the daemon
  eduvpn-radius.py --test IP [config]    send one test Start/Stop pair
  Default config: /etc/eduvpn-radius/eduvpn-radius.conf
"""

import argparse
import configparser
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sys
import time
import uuid
from typing import Dict, NoReturn, Optional

try:
    from pyrad.client import Client, Timeout
    from pyrad.dictionary import Dictionary
    HAS_PYRAD = True
except ImportError:
    HAS_PYRAD = False

    class Timeout(Exception):  # lets the module load (and be tested) without pyrad
        pass

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
DEFAULT_CONFIG = "/etc/eduvpn-radius/eduvpn-radius.conf"
DEFAULT_STATE  = "/var/lib/eduvpn-radius/state.json"
DEFAULT_LOG    = "/var/log/eduvpn/eduvpn.log"
DICT_PATH      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dictionary")
RETRY_SEC      = 30.0   # how often unconfirmed Accounting-Starts are re-sent
                        # (also: how long sends are skipped after a timeout)
POLL_SEC       = 0.3    # log polling interval at EOF
SAVE_SEC       = 1.0    # min interval between state saves while reading a backlog
EXIT_CONFIG    = 2      # bad configuration: systemd must not restart-loop on it

START, STOP, INTERIM = 1, 2, 3
_STATUS = {START: "Start", STOP: "Stop", INTERIM: "Interim-Update"}

# --------------------------------------------------------------------------
# Global state
# --------------------------------------------------------------------------
logger = logging.getLogger("eduvpn-radius")

# Active sessions: conn (WireGuard public key) → {user, ip4, ip6, profile,
# acct_session_id, ok}; ok = the last Accounting-Start was answered.
sessions: Dict[str, dict] = {}
# Position reached in the log: inode of the file being read and byte offset of
# the first unprocessed line. Saved together with the sessions.
log_pos: Dict[str, int] = {}

cfg: Dict[str, str] = {}
radius_client: Optional["Client"] = None
state_path: str = DEFAULT_STATE
_shutdown = False
_next_retry = 0.0  # 0 = retry at the first EOF (sessions restored from state)
_next_interim = 0.0
_down_until = 0.0  # FortiGate timed out: skip sends until then (see _send)
_dirty = False     # sessions changed since the last save
_last_save = 0.0

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


def _ip(value: Optional[str]) -> str:
    # "-" for missing or malformed addresses: pyrad would reject the whole packet.
    try:
        return str(ipaddress.ip_address(value or ""))
    except ValueError:
        return "-"


# --------------------------------------------------------------------------
# State persistence
# --------------------------------------------------------------------------
def _load_state() -> None:
    """Loads sessions and log position. Restored sessions are marked not
    confirmed (ok=False): their Accounting-Start is re-sent once the backlog
    has been read."""
    global sessions, log_pos
    sessions, log_pos = {}, {}
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    except Exception as e:
        # A corrupted or unreadable state file must never prevent the start.
        logger.warning("Could not load state file %s, starting empty: %s", state_path, e)
        return
    if not isinstance(data, dict):
        logger.warning("State file %s has unexpected format, starting empty", state_path)
        return
    if isinstance(data.get("sessions"), dict):
        raw = data["sessions"]
        pos = data.get("log")
        if isinstance(pos, dict) and isinstance(pos.get("ino"), int) and isinstance(pos.get("pos"), int):
            log_pos = {"ino": pos["ino"], "pos": pos["pos"]}
    else:
        raw = data  # format of the first release: {conn: session}, no position
    for conn, sess in raw.items():
        if isinstance(sess, dict) and sess.get("user") and sess.get("acct_session_id"):
            sessions[conn] = dict(sess, ip4=_ip(sess.get("ip4")), ip6=_ip(sess.get("ip6")),
                                  profile=sess.get("profile") or "-", ok=False)


def _changed() -> None:
    global _dirty
    _dirty = True


def _maybe_save(force: bool = False) -> None:
    # Saving after every event made a backlog of thousands of events with
    # thousands of open sessions crawl (one full JSON rewrite per line). Sessions
    # and position are saved together, so a crash only replays the last second.
    if _dirty and (force or time.monotonic() - _last_save >= SAVE_SEC):
        _save_state()


def _save_state() -> None:
    global _dirty, _last_save
    _dirty, _last_save = False, time.monotonic()
    tmp = state_path + ".tmp"
    try:
        state_dir = os.path.dirname(state_path)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"log": log_pos, "sessions": sessions}, f, indent=1)
        os.replace(tmp, state_path)
    except Exception as e:
        logger.warning("Could not save state: %s", e)


# --------------------------------------------------------------------------
# RADIUS
# --------------------------------------------------------------------------
def _make_session_id() -> str:
    return uuid.uuid4().hex[:16]


def _send(status_type: int, sess: dict, probe: bool = False) -> bool:
    """Sends Accounting-Start, -Stop or Interim-Update. True if FortiGate answered.
    After a timeout, sends are skipped for RETRY_SEC: otherwise every event of
    a FortiGate outage would stall the log for 10 s. Retry, interim and shutdown
    rounds pass probe=True to try anyway."""
    global _down_until
    if radius_client is None:
        return False
    if not probe and time.monotonic() < _down_until:
        return False
    try:
        pkt = radius_client.CreateAcctPacket()
        pkt["User-Name"]        = sess["user"]
        pkt["Acct-Status-Type"] = _STATUS[status_type]
        pkt["Acct-Session-Id"]  = sess["acct_session_id"]
        pkt["NAS-Identifier"]   = cfg["nas_identifier"]
        if sess.get("profile", "-") not in ("-", ""):
            pkt["Called-Station-Id"] = sess["profile"]
        if sess.get("ip4", "-") != "-":
            pkt["Framed-IP-Address"] = sess["ip4"]
        if sess.get("ip6", "-") != "-":
            pkt["Framed-IPv6-Address"] = sess["ip6"]
        radius_client.SendPacket(pkt)
        _down_until = 0.0
        return True
    except Timeout:
        logger.warning("RADIUS timeout towards %s:%s (sends paused for %ds)",
                       cfg.get("server", "?"), cfg.get("port", "?"), RETRY_SEC)
        _down_until = time.monotonic() + RETRY_SEC
        return False
    except Exception as e:
        logger.warning("RADIUS error: %s", e)
        return False


def _start(conn: str, sess: dict, why: str, probe: bool = False) -> None:
    sess["ok"] = _send(START, sess, probe)
    logger.info("start(%s) user=%s ip4=%s ip6=%s profile=%s ok=%s conn=%.12s",
                why, sess["user"], sess["ip4"], sess["ip6"], sess["profile"], sess["ok"], conn)


def _stop(conn: str, sess: dict, why: str, probe: bool = False) -> bool:
    ok = _send(STOP, sess, probe)
    logger.info("stop(%s) user=%s ip4=%s ip6=%s profile=%s ok=%s conn=%.12s",
                why, sess["user"], sess["ip4"], sess["ip6"], sess["profile"], ok, conn)
    return ok


# --------------------------------------------------------------------------
# Log event handlers
# --------------------------------------------------------------------------
def handle_connect(kv: Dict[str, str]) -> None:
    conn    = kv.get("conn", "")
    user    = kv.get("user", "-")
    ip4     = _ip(kv.get("tunnel_ip4"))
    ip6     = _ip(kv.get("tunnel_ip6"))
    profile = kv.get("profile", "-")

    if not conn or user in ("-", ""):
        return  # unattributed peer: nothing FortiGate could use
    if ip4 == "-" and ip6 == "-":
        logger.warning("connect without tunnel IP ignored user=%s conn=%.12s", user, conn)
        return

    old = sessions.get(conn)
    if old is not None:
        if (old["user"], old["ip4"], old["ip6"]) == (user, ip4, ip6):
            # Same session announced again (eduvpn-logger re-announces active
            # peers after its own restart): refresh, keep the session id.
            _start(conn, old, "refresh")
            _changed()
            return
        sessions.pop(conn)
        _stop(conn, old, "replaced")

    # The VPN pool reassigns freed IPs: if a *different* tracked session still
    # holds this ip4/ip6, its disconnect was missed and it is provably dead.
    # Close it, or its user→IP mapping would be replayed over the new user's.
    for other_conn, other in list(sessions.items()):
        if (ip4 != "-" and other["ip4"] == ip4) or (ip6 != "-" and other["ip6"] == ip6):
            sessions.pop(other_conn)
            _stop(other_conn, other, "ip-reassigned")

    sess = {"user": user, "ip4": ip4, "ip6": ip6, "profile": profile,
            "acct_session_id": _make_session_id(), "ok": False}
    sessions[conn] = sess
    _start(conn, sess, "connect")
    _changed()


def handle_disconnect(kv: Dict[str, str]) -> None:
    conn = kv.get("conn", "")
    if not conn:
        return
    sess = sessions.pop(conn, None)
    if sess is None:
        logger.info("disconnect for untracked session user=%s conn=%.12s", kv.get("user", "-"), conn)
        return
    _stop(conn, sess, "disconnect")
    _changed()


def process_line(line: str) -> None:
    # "<ISO-8601 timestamp> event=connect user=... conn=... tunnel_ip4="..." ..."
    _ts, _sep, rest = line.strip().partition(" ")
    if "event=" not in rest:
        return
    kv = parse_kv(rest)
    event = kv.get("event")
    if event == "connect":
        handle_connect(kv)
    elif event == "disconnect":
        handle_disconnect(kv)
    # roam: the tunnel IP does not change, the FortiGate mapping stays valid.


# --------------------------------------------------------------------------
# Retry of unconfirmed Accounting-Starts (also the recovery after a restart)
# --------------------------------------------------------------------------
def retry_starts() -> None:
    global _next_retry
    now = time.monotonic()
    if now < _next_retry:
        return
    _next_retry = now + RETRY_SEC
    pending = [(c, s) for c, s in sessions.items() if not s.get("ok")]
    if not pending:
        return
    logger.info("Sending Accounting-Start for %d unconfirmed session(s)", len(pending))
    for conn, sess in pending:
        _start(conn, sess, "retry", probe=True)
        if not sess["ok"]:
            break  # FortiGate unreachable: try the rest in RETRY_SEC, don't block
    _changed()


def send_interims() -> None:
    # FortiGate removes an RSSO user after rsso-context-timeout (default 8 h)
    # without accounting for it, so long sessions would lose their identity.
    # An Interim-Update resets that timer (a repeated Start could flush the
    # user's firewall sessions when rsso-flush-ip-session is enabled).
    global _next_interim
    interval = int(cfg.get("interim_interval", "0"))
    now = time.monotonic()
    if not interval or now < _next_interim:
        return
    confirmed = [(c, s) for c, s in sessions.items() if s.get("ok")]
    for n, (conn, sess) in enumerate(confirmed):
        if not _send(INTERIM, sess, probe=True):
            logger.warning("Interim-Update failed after %d of %d session(s); retrying in %ds",
                           n, len(confirmed), RETRY_SEC)
            _next_interim = now + RETRY_SEC
            return
    if confirmed:
        logger.info("Interim-Update sent for %d session(s)", len(confirmed))
    _next_interim = now + interval


# --------------------------------------------------------------------------
# Log follower
# --------------------------------------------------------------------------
def _process_bytes(raw: bytes) -> None:
    try:
        process_line(raw.decode("utf-8", errors="replace"))
    except Exception as e:  # one bad line must never stop the follower
        logger.error("Error processing line %r: %s", raw[:200], e)


def _read_lines(f, ino: int, final: bool = False) -> None:
    """Processes the complete lines available in f, keeping log_pos after the
    last processed one. A trailing line without newline is still being
    written: it is left for the next read, unless final (file rotated away)."""
    while not _shutdown:
        start = f.tell()
        raw = f.readline()
        if not raw:
            return
        if not raw.endswith(b"\n") and not final:
            f.seek(start)
            return
        log_pos["ino"], log_pos["pos"] = ino, f.tell()
        _process_bytes(raw)
        _maybe_save()


def _find_rotated(log_path: str, ino: int) -> Optional[str]:
    # The file we were reading when the daemon stopped, renamed by logrotate
    # (eduvpn.log-YYYYMMDD; delaycompress keeps the first rotation uncompressed).
    # ponytail: compressed (.gz) rotations are not searched; a downtime spanning
    # two rotations loses the tail of the older file.
    d = os.path.dirname(log_path) or "."
    base = os.path.basename(log_path)
    try:
        for e in os.scandir(d):
            if e.name.startswith(base) and e.name != base and e.is_file() and e.inode() == ino:
                return e.path
    except OSError:
        pass
    return None


def _catch_up_rotated(log_path: str) -> None:
    # On start, if the saved position belongs to a file that has since been
    # rotated, finish reading that file before switching to the current one.
    ino = log_pos["ino"]
    try:
        if os.stat(log_path).st_ino == ino:
            return
    except FileNotFoundError:
        pass
    old = _find_rotated(log_path, ino)
    if old is None:
        logger.warning("Saved log position is in a file no longer found; reading %s from the start", log_path)
        return
    logger.info("Log rotated while stopped: reading the rest of %s", old)
    with open(old, "rb") as f:
        f.seek(log_pos["pos"])
        _read_lines(f, ino, final=True)


def follow_log(log_path: str) -> None:
    # Where to start the first open: the saved position if it belongs to this
    # file, else the start of the file (new since the saved position). Only
    # without any saved position (first run) the existing lines are skipped.
    first = True
    if log_pos:
        _catch_up_rotated(log_path)
    while not _shutdown:
        try:
            with open(log_path, "rb") as f:
                st = os.fstat(f.fileno())
                ino = st.st_ino
                if first and not log_pos:
                    f.seek(0, 2)
                elif first and log_pos.get("ino") == ino and log_pos["pos"] <= st.st_size:
                    f.seek(log_pos["pos"])
                first = False
                log_pos["ino"], log_pos["pos"] = ino, f.tell()
                logger.info("Following %s from byte %d", log_path, f.tell())

                while not _shutdown:
                    _read_lines(f, ino)
                    if _shutdown:
                        break
                    retry_starts()
                    send_interims()
                    _maybe_save(force=True)
                    time.sleep(POLL_SEC)
                    # Rotated (inode changed or file gone): drain what was still
                    # appended to the old file, then reopen. Truncated in place
                    # (copytruncate: size below our offset): reopen from 0.
                    try:
                        st = os.stat(log_path)
                        if st.st_ino != ino:
                            logger.info("Log rotated, reopening")
                            _read_lines(f, ino, final=True)
                            break
                        if st.st_size < f.tell():
                            logger.info("Log truncated, reopening")
                            break
                    except FileNotFoundError:
                        _read_lines(f, ino, final=True)
                        break
        except FileNotFoundError:
            first = False  # when it appears, all of its content is new
            logger.warning("Log file not found: %s — retrying in 10s", log_path)
            _sleep(10)
        except Exception as e:
            logger.error("Error in log follower: %s — retrying in 5s", e)
            _sleep(5)


def _sleep(seconds: float) -> None:
    end = time.monotonic() + seconds
    while not _shutdown and time.monotonic() < end:
        time.sleep(POLL_SEC)


# --------------------------------------------------------------------------
# Shutdown
# --------------------------------------------------------------------------
def _handle_signal(signum, frame) -> None:
    # Only a flag: the main loop finishes the current line, then stop_all() runs.
    global _shutdown
    _shutdown = True


def stop_all() -> None:
    # Save first (sessions kept: they are re-started on the next run), then
    # tell FortiGate the mappings are gone. If FortiGate does not answer, stop
    # trying: TimeoutStopSec would kill us anyway.
    _save_state()
    if sessions:
        logger.info("Shutdown: sending Accounting-Stop for %d session(s)", len(sessions))
    for conn, sess in list(sessions.items()):
        if not _stop(conn, sess, "shutdown", probe=True):
            logger.warning("FortiGate not answering: remaining sessions not stopped")
            break


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def _config_error(msg: str, *args) -> NoReturn:
    logger.error(msg, *args)
    sys.exit(EXIT_CONFIG)


def _parse_config(parser: configparser.ConfigParser, config_path: str) -> Dict[str, str]:
    try:
        c = {
            "server":         parser.get("radius", "server").strip(),
            "port":           parser.get("radius", "port", fallback="1813").strip(),
            "secret":         parser.get("radius", "secret").strip(),
            "nas_identifier": parser.get("radius", "nas_identifier", fallback="").strip() or socket.gethostname(),
            "interim_interval": parser.get("radius", "interim_interval", fallback="3600").strip(),
            "log_path":       parser.get("eduvpn", "log_path", fallback=DEFAULT_LOG).strip(),
            "state_path":     parser.get("eduvpn", "state_path", fallback=DEFAULT_STATE).strip(),
        }
    except configparser.Error as e:
        _config_error("Invalid configuration in %s: %s", config_path, e)
    if not c["server"]:
        _config_error("%s: [radius] server is empty", config_path)
    if not c["port"].isdigit() or not 0 < int(c["port"]) < 65536:
        _config_error("%s: [radius] port must be a number between 1 and 65535", config_path)
    if not c["secret"] or c["secret"].startswith("CHANGE_ME"):
        _config_error("%s: [radius] secret is not set (still the placeholder?)", config_path)
    if not c["interim_interval"].isdigit() or 0 < int(c["interim_interval"]) < 60:
        _config_error("%s: [radius] interim_interval must be 0 (off) or at least 60 seconds", config_path)
    return c


def _load_config(config_path: str) -> Dict[str, str]:
    parser = configparser.ConfigParser()
    try:
        read_ok = parser.read(config_path)
    except configparser.Error as e:
        _config_error("Invalid configuration syntax in %s: %s", config_path, e)
    if not read_ok:
        _config_error("Could not read configuration file: %s", config_path)
    return _parse_config(parser, config_path)


def _make_client() -> "Client":
    if not os.path.isfile(DICT_PATH):
        logger.error("RADIUS dictionary not found: %s", DICT_PATH)
        sys.exit(1)
    try:
        client = Client(server=cfg["server"], authport=1812, acctport=int(cfg["port"]),
                        secret=cfg["secret"].encode(), dict=Dictionary(DICT_PATH))
    except Exception as e:
        logger.error("Could not initialize RADIUS client: %s", e)
        sys.exit(1)
    client.timeout = 5
    client.retries = 2
    return client


def run_test(ip: str) -> int:
    """Sends a Start and, after ENTER, the matching Stop for a test user."""
    ip = _ip(ip)
    if ip == "-":
        logger.error("--test needs a valid IPv4 or IPv6 address")
        return EXIT_CONFIG
    v6 = ":" in ip
    sess = {"user": "eduvpn-radius-test", "ip4": "-" if v6 else ip, "ip6": ip if v6 else "-",
            "profile": "test", "acct_session_id": _make_session_id()}
    print(f"Accounting-Start user={sess['user']} ip={ip} to {cfg['server']}:{cfg['port']} "
          f"(NAS-Identifier={cfg['nas_identifier']})")
    if not _send(START, sess):
        print("FAILED: no answer. Check address, port, shared secret and that FortiGate accepts RADIUS accounting from this host.")
        return 1
    print("OK: FortiGate answered. Its RSSO user list should now map the test user to that IP.")
    try:
        input("Press ENTER to send the Accounting-Stop... ")
    except EOFError:
        pass
    ok = _send(STOP, sess)
    print("OK: Stop answered, the entry should be gone." if ok else "FAILED: no answer to the Stop.")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main() -> None:
    global cfg, radius_client, state_path, _next_interim

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",  # journald adds time and identifier
        stream=sys.stdout,
    )
    ap = argparse.ArgumentParser(description="eduVPN → FortiGate RSSO RADIUS Accounting daemon")
    ap.add_argument("config", nargs="?", default=DEFAULT_CONFIG)
    ap.add_argument("--test", metavar="IP", help="send one test Accounting-Start/Stop for IP and exit")
    args = ap.parse_args()

    if not HAS_PYRAD:
        logger.error("pyrad is not installed. Install it with: apt install python3-pyrad")
        sys.exit(1)

    cfg = _load_config(args.config)
    radius_client = _make_client()
    if args.test:
        sys.exit(run_test(args.test))

    state_path = cfg["state_path"]
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _load_state()
    _next_interim = time.monotonic() + int(cfg["interim_interval"])
    logger.info("Started: FortiGate %s:%s, %d session(s) restored", cfg["server"], cfg["port"], len(sessions))
    follow_log(cfg["log_path"])
    stop_all()


if __name__ == "__main__":
    main()
