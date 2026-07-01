# eduvpn-fortigate-rsso

*🇮🇹 [Leggi in italiano](README.it.md)*

**RADIUS Accounting bridge from eduVPN WireGuard sessions to FortiGate RSSO identity-based firewall policies.**

## Motivation

In a **No-NAT** eduVPN deployment, packets from VPN clients reach the
FortiGate with their real VPN pool IP as source (e.g. `10.20.0.5`). FortiGate
has no native eduVPN integration, so out of the box its firewall policies and
logs only ever see an IP address — never the user behind it. That is a real
gap for audit, incident response, and identity-based access control.

FortiGate does understand a standard mechanism for this: **RADIUS Accounting**
(RFC 2866). Its RSSO (RADIUS Single Sign-On) agent listens for
Accounting-Start/Stop packets from a NAS and builds an internal user↔IP
mapping table that firewall policies can reference directly.

`eduvpn-fortigate-rsso` is a small daemon that acts as that NAS: it tails the
unified session log produced by [eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger)
(or any correlator emitting the same `event=` log format) and turns
`connect`/`disconnect` events into RADIUS Accounting-Start/Stop packets sent to
your FortiGate.

```
eduVPN gateway (vpn.example.org)             FortiGate
─────────────────────────────                ─────────
correlator → /var/log/eduvpn/eduvpn.log
                    ↓
            eduvpn-radius.py
                    ↓ UDP/1813
              Acct-Start/Stop  ──────────→ RSSO table
                                           user alice → 10.20.0.5
                                           user alice → 2001:db8:1234:5678::5
                                           ↓
                                     firewall policy
                                     src: 10.20.0.0/22
                                     identity: user → log/ACL
```

## Design highlights

Extracted from a production university deployment and generalised. A few
decisions worth calling out:

- **Session persistence with crash-safe recovery.** Active sessions are
  serialised to a JSON state file after every event (atomic write: temp file +
  `os.replace`). On restart the daemon re-sends Accounting-Start for every
  persisted session, so a daemon restart never leaves FortiGate's RSSO table
  stale.
- **Roaming is a RADIUS no-op.** A WireGuard client's assigned VPN IP never
  changes when it roams (e.g. WiFi → LTE) — only its external source IP does.
  The FortiGate user→VPN_IP mapping is unaffected, so `event=roam` triggers no
  RADIUS traffic at all.
- **Rapid-reconnect handling.** If a `connect` arrives for a WireGuard peer
  that already has an active session (same public key), the daemon closes the
  old session (Accounting-Stop) before opening the new one — no orphaned
  entries in FortiGate's table.
- **Graceful shutdown.** On SIGTERM/SIGINT the daemon sends Accounting-Stop for
  every active session before exiting, so a planned restart or stop never
  leaves stale RSSO entries behind (`TimeoutStopSec=30` in the systemd unit
  gives it time to do so).
- **No embedded site identity.** `NAS-Identifier` defaults to the local
  hostname if not set explicitly in the config — nothing site-specific is
  hardcoded in the script.

## How it works

| Correlator event | RADIUS action | Why |
|---|---|---|
| `event=connect` | Accounting-Start | New VPN session, IP assigned |
| `event=disconnect` | Accounting-Stop | Session ended, remove the mapping |
| `event=roam` | none | The VPN IP doesn't change on roam; only the external source IP does |

Each active session is tracked in memory (and persisted to the state file),
keyed by the WireGuard public key (`conn`):

```json
{
  "ABCDEF123...": {
    "user": "alice",
    "ip4": "10.20.0.5",
    "ip6": "2001:db8:1234:5678::5",
    "profile": "staff",
    "acct_session_id": "a1b2c3d4e5f60001"
  }
}
```

`acct_session_id` (a 16-char UUID hex) lets FortiGate match an
Accounting-Stop to the correct Accounting-Start, even with concurrent
sessions from the same user on different profiles. It is used internally and
does not appear in the FortiGate dashboard — that's expected.

## Requirements

- Linux with `systemd`.
- Python 3.9+ and [`pyrad`](https://github.com/pyradius/pyrad) (installed
  automatically by `install.sh`).
- A correlator producing the `event=connect|roam|disconnect` log format —
  e.g. [eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger).
- A FortiGate with RSSO support (tested on FortiOS 7.4.x).

## Quick start

```bash
git clone https://github.com/giacomocamata/eduvpn-fortigate-rsso.git
cd eduvpn-fortigate-rsso
chmod +x install.sh
sudo ./install.sh
```

`install.sh` is idempotent. On a **fresh install** it does not start the
service — it ships only a placeholder configuration (no real secret would
work), so it installs `eduvpn-radius.conf.example` as your config and prints
the next steps below. On a **re-run** where a real config already exists, it
leaves that config untouched and (re)starts the service.

## Post-install steps

### 1. Edit the configuration

```bash
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf
```

Set `server` to your FortiGate's real IP and generate a real `secret`
(`openssl rand -base64 24`). See [Configuration reference](#configuration-reference)
for all keys.

### 2. Configure FortiGate to consume the accounting data

This daemon's only job is to speak standard RADIUS Accounting (RFC 2866) to
FortiGate; how FortiGate turns that into identity-aware firewall policies is
configured entirely on the FortiGate side, through its RADIUS Single Sign-On
(RSSO) feature, and is independent of this repository.

At a conceptual level, four things need to exist on FortiGate — regardless
of FortiOS version or GUI layout:

1. **Accounting reception** on the interface facing this daemon, for the
   port configured in `eduvpn-radius.conf` (default UDP 1813).
2. **An RSSO agent** (a "RADIUS Single Sign-On agent" / External Connector
   in FortiOS), configured with the same shared `secret` as this daemon, and
   told which RADIUS attribute carries the client's IP and which carries its
   group/context — see [Data sent to FortiGate](#data-sent-to-fortigate)
   below for the exact attributes this daemon populates.
3. **A user group** of type RSSO referencing that agent, so firewall
   policies can select "every user this daemon reports".
4. **A firewall policy** whose source covers your VPN address pool(s) and
   references that RSSO group, turning its logs and access control
   identity-aware.

The exact CLI commands and GUI screens for these steps change between
FortiOS releases, so this README deliberately doesn't keep a copy of them —
follow Fortinet's own, version-matched documentation instead:

- [Fortinet Document Library](https://docs.fortinet.com/) — search "RADIUS
  Single Sign-On" or "RSSO agent" for your FortiOS version
- e.g. [Configuring RADIUS SSO authentication (FortiOS 7.6)](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/513092/configuring-radius-sso-authentication)

## Configuration reference

`eduvpn-radius.conf` is an INI file (see
[`eduvpn-radius.conf.example`](eduvpn-radius.conf.example) for the shipped
template):

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[radius]` | `server` | *(required)* | FortiGate IP receiving Accounting packets |
| `[radius]` | `port` | `1813` | RADIUS Accounting port |
| `[radius]` | `secret` | *(required)* | Shared secret, must match the FortiGate RSSO agent |
| `[radius]` | `nas_identifier` | local hostname | `NAS-Identifier` sent in every packet |
| `[eduvpn]` | `log_path` | `/var/log/eduvpn/eduvpn.log` | Correlator log to follow |
| `[eduvpn]` | `state_path` | `/var/lib/eduvpn-radius/state.json` | Session persistence file |

## Data sent to FortiGate

This is the RADIUS Accounting data contract this daemon implements — map
these attributes on FortiGate's RSSO agent to make use of them:

| Parameter | Value |
|---|---|
| RADIUS Accounting port | UDP `1813` (or your configured `port`) |
| Endpoint (IP) attribute | `Framed-IP-Address` (+ `Framed-IPv6-Address` for IPv6) |
| Group/context attribute | `Called-Station-Id` (the VPN profile name) |
| Session matching attribute | `Acct-Session-Id` (pairs each Stop with its Start) |

## Testing connectivity

A minimal test script sends an Accounting-Start (with IPv4 **and** IPv6),
pauses so you can inspect the FortiGate RSSO table, then sends an
Accounting-Stop to clean up:

```bash
sudo tee /tmp/radius-test.py > /dev/null << 'PYEOF'
from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
import uuid, sys

FORTIGATE  = "203.0.113.1"
SECRET     = b"CHANGE_ME_use_a_long_random_secret"
DICT_PATH  = "/usr/local/lib/eduvpn-radius/dictionary"
NAS_ID     = "vpn.example.org"
TEST_USER  = "connectivity_test"
TEST_IP4   = "10.20.0.99"
TEST_IP6   = "2001:db8:1234:5678::99"
TEST_PROF  = "staff"
SESSION_ID = uuid.uuid4().hex[:16]

d = Dictionary(DICT_PATH)
c = Client(server=FORTIGATE, authport=1812, acctport=1813, secret=SECRET, dict=d)
c.timeout = 5
c.retries = 1

print("[1/2] Accounting-Start")
print(f"      user={TEST_USER}  ip4={TEST_IP4}  ip6={TEST_IP6}")
print(f"      profile={TEST_PROF}  session={SESSION_ID}")
pkt = c.CreateAcctPacket()
pkt["User-Name"]           = TEST_USER
pkt["Acct-Status-Type"]    = "Start"
pkt["Acct-Session-Id"]     = SESSION_ID
pkt["NAS-Identifier"]      = NAS_ID
pkt["Framed-IP-Address"]   = TEST_IP4
pkt["Framed-IPv6-Address"] = TEST_IP6
pkt["Called-Station-Id"]   = TEST_PROF
try:
    c.SendPacket(pkt)
    print("      OK — Start accepted")
except Timeout:
    print("      ERROR Timeout — FortiGate not responding on UDP/1813")
    print("      Check that the receiving interface accepts RADIUS Accounting")
    print(f"      Check routing: ip route get {FORTIGATE}")
    sys.exit(1)
except Exception as e:
    print(f"      ERROR: {e}")
    sys.exit(1)

print()
print("Now check FortiGate's RSSO / authenticated-users status (GUI or")
print("diagnostic CLI, per Fortinet's documentation) for a 'connectivity_test'")
print("entry mapped to the IPs above.")
print()
input("Press ENTER to send Accounting-Stop and clean up...")
print()

print("[2/2] Accounting-Stop")
print(f"      user={TEST_USER}  ip4={TEST_IP4}  ip6={TEST_IP6}")
pkt2 = c.CreateAcctPacket()
pkt2["User-Name"]           = TEST_USER
pkt2["Acct-Status-Type"]    = "Stop"
pkt2["Acct-Session-Id"]     = SESSION_ID
pkt2["NAS-Identifier"]      = NAS_ID
pkt2["Framed-IP-Address"]   = TEST_IP4
pkt2["Framed-IPv6-Address"] = TEST_IP6
try:
    c.SendPacket(pkt2)
    print("      OK — Stop accepted. Both entries (IPv4 and IPv6) removed.")
except Exception as e:
    print(f"      ERROR on Stop: {e}")

print()
print("Final check: confirm on FortiGate that the 'connectivity_test' entry")
print("is now gone from its RSSO / authenticated-users status.")
PYEOF

python3 /tmp/radius-test.py
```

While the script is paused between Start and Stop, FortiGate's own packet
capture and RSSO/authenticated-users diagnostic tools (GUI or CLI, documented
by Fortinet for your FortiOS version — see the links above) let you confirm
the packets arrived and the mapping was created, before the Stop removes it
again.

## Troubleshooting

Most issues fall on one of two sides:

- **This daemon isn't sending, or is sending the wrong data** — check
  `sudo journalctl -u eduvpn-radius -f`: connect/disconnect events, RADIUS
  timeouts, and configuration errors are all logged there in plain language
  (see [Configuration reference](#configuration-reference)).
- **FortiGate isn't receiving it, or isn't acting on it** — using Fortinet's
  own diagnostic tools for your FortiOS version, verify that: the receiving
  interface accepts RADIUS Accounting on the configured port; the RSSO
  agent's shared secret matches this daemon's `secret`; the RSSO agent's
  endpoint/group attribute mapping matches
  [Data sent to FortiGate](#data-sent-to-fortigate); and the firewall policy
  actually references the RSSO group.

The exact packet-capture, RADIUS-debug, and authenticated-users commands are
covered in Fortinet's documentation (see the links in
[Post-install steps](#post-install-steps)) rather than duplicated here, since
they're more likely to stay accurate across FortiOS releases than a copy
kept in this README.

### Common symptoms

| Symptom | Likely side | What to check |
|---|---|---|
| `RADIUS timeout` in the daemon log | FortiGate / network | Accounting reception enabled on the right interface and port; routing/firewalling between the two hosts |
| Daemon logs `ok=True` but nothing shows up on FortiGate | FortiGate | RSSO agent's shared secret and attribute mapping |
| FortiGate shows the IP but no group/username label | FortiGate | RSSO agent's group/context attribute mapping |
| Entries never disappear after disconnect | FortiGate | RSSO agent's session-flush behaviour |
| Log file not found at startup | This daemon / correlator | The correlator (e.g. eduvpn-logger) isn't running yet — the daemon retries every 10s |

## Manual install

```bash
sudo mkdir -p /usr/local/lib/eduvpn-radius
sudo install -m 0755 eduvpn-radius.py /usr/local/lib/eduvpn-radius/
sudo install -m 0644 dictionary README.md /usr/local/lib/eduvpn-radius/

sudo mkdir -p /etc/eduvpn-radius
sudo install -m 0640 eduvpn-radius.conf.example /etc/eduvpn-radius/eduvpn-radius.conf
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf   # set real server + secret

sudo mkdir -p /var/lib/eduvpn-radius
sudo install -m 0644 systemd/eduvpn-radius.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now eduvpn-radius.service
```

## Security considerations

The daemon runs as `root` (it needs to read the correlator log, write the
state file, and read a config file containing a shared secret) — this
matches the production setup this was extracted from. The config file is
installed with `chmod 640` to keep the secret non-world-readable. If you want
to reduce the daemon's privileges further, consider adding systemd hardening
directives to the unit (`ProtectSystem=strict`, `ProtectHome=true`,
`ReadWritePaths=/var/lib/eduvpn-radius`) — not implemented here, but a
reasonable next step if your threat model calls for it.

## Maintenance

```bash
# Live logs
sudo journalctl -u eduvpn-radius -f
sudo journalctl -u eduvpn-radius --since "1 hour ago"

# Active session state
sudo cat /var/lib/eduvpn-radius/state.json | python3 -m json.tool

# Restart (Accounting-Start is automatically re-sent for all persisted sessions)
sudo systemctl restart eduvpn-radius

# Rotate the shared secret
openssl rand -base64 24
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf   # update secret
sudo systemctl restart eduvpn-radius
# then update the same secret on FortiGate's RSSO agent — see Fortinet's
# documentation (linked in "Post-install steps") for your FortiOS version
```

## Testing

```bash
python3 test_eduvpn_radius.py
```

Covers the pure logic worth protecting: KV log-line parsing, atomic session
state save/load, rapid-reconnect session replacement, and disconnect
handling — with no `pyrad` install or network access required.

## License

MIT — see [LICENSE](LICENSE).
