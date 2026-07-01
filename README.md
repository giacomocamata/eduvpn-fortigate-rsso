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

### 2. Enable RADIUS Accounting reception on FortiGate

FortiGate does not accept RADIUS Accounting packets on any interface by
default — enable it on the interface that receives traffic from your eduVPN
gateway.

Find the right interface (the one whose subnet includes your gateway's IP):
```
get system interface physical
```

Via CLI:
```
config system interface
    edit "<interface-name>"
        append allowaccess radius-acct
    next
end
```
Verify: `show system interface <interface-name> | grep allowaccess` should
list `radius-acct`.

Via GUI: **Network → Interfaces** → select the interface → **Edit** →
**Administrative Access** → check **RADIUS Accounting** → **OK**.

### 3. Create the RSSO Agent (External Connector)

In FortiOS 7.4, the RSSO agent lives under **Security Fabric → External
Connectors**, not under User & Authentication → RADIUS Servers. `set server`
is not a valid parameter here — the agent is a local listener on port 1813,
accepting packets from any source with the correct secret.

| CLI parameter | Role |
|---|---|
| `rsso-endpoint-attribute` | RADIUS attribute carrying the client's **IP** |
| `sso-attribute` | RADIUS attribute carrying the user's **group/context** — needed for the group to show up in the dashboard |

Via CLI:
```
config user radius
    edit "eduvpn-rsso"
        set rsso enable
        set rsso-secret "CHANGE_ME_use_a_long_random_secret"
        set rsso-radius-response enable
        set rsso-endpoint-attribute Framed-IP-Address
        set sso-attribute Called-Station-Id
        set rsso-flush-ip-session enable
        set rsso-log-flags all
    next
end
```
Verify: `show user radius eduvpn-rsso` (the secret is shown encrypted).

Via GUI: **Security Fabric → External Connectors → Create New →
RADIUS Single Sign-On Agent**, fill in Name (`eduvpn-rsso`), the shared
secret, enable **Send RADIUS Responses**, set Endpoint Attribute to
`Framed-IP-Address` and SSO Attribute to `Called-Station-Id`, enable
**Flush Endpoint IP Sessions**.

A ready-to-paste version of all CLI blocks in this section is in
[`examples/fortigate-rsso-cli.conf`](examples/fortigate-rsso-cli.conf).

### 4. Create the RSSO user group

```
config user group
    edit "eduvpn-vpn-users"
        set group-type rsso
        set member "eduvpn-rsso"
    next
end
```

### 5. Reference the group in a firewall policy

```
config firewall policy
    edit 0
        set name "eduvpn-users-internet"
        set srcintf "<inbound-interface>"
        set dstintf "<outbound-interface>"
        set srcaddr "10.20.0.0/22"
        set dstaddr "all"
        set groups "eduvpn-vpn-users"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set logtraffic-start enable
    next
end
```

> Replace `10.20.0.0/22` with the aggregate covering every VPN address pool
> you assign to eduVPN profiles.

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

## RSSO attribute mapping

| Parameter | Value |
|---|---|
| RADIUS Accounting port | UDP `1813` |
| Endpoint (IP) attribute | `Framed-IP-Address` (+ `Framed-IPv6-Address` for IPv6) |
| Group/context attribute | `Called-Station-Id` (the VPN profile name) |

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
    print("      Check allowaccess radius-acct on the interface")
    print(f"      Check routing: ip route get {FORTIGATE}")
    sys.exit(1)
except Exception as e:
    print(f"      ERROR: {e}")
    sys.exit(1)

print()
print("Now verify on FortiGate:")
print("  diagnose test application radiusd 6")
print("  diagnose firewall auth list")
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
print("Final check on FortiGate:")
print("  diagnose test application radiusd 6")
print("  (should be empty or not contain connectivity_test)")
PYEOF

python3 /tmp/radius-test.py
```

### Synchronized test procedure

On **FortiGate**, open a sniffer in a separate SSH session before running the
script:
```
diagnose sniffer packet any "host <NAS-IP> and udp port 1813" 6 0 l
```

On the **eduVPN gateway**, run the script: `python3 /tmp/radius-test.py`. The
sniffer should show 2 packets (Start + response). While the script is
paused, check `diagnose test application radiusd 6` — you should see
`connectivity_test` with `10.20.0.99` and `2001:db8:1234:5678::99` — and
`diagnose firewall auth list`, which should show `type: rsso` and
`group_name: eduvpn-vpn-users`. Press ENTER; the sniffer shows 2 more packets
(Stop + response), and both entries should disappear from
`diagnose test application radiusd 6`.

## Debugging on FortiGate

> FortiGate may handle RADIUS for other purposes too. All commands below
> filter explicitly for the eduVPN gateway's IP so they don't interfere with
> other RADIUS agents already configured.

Pre-flight checks (no traffic generated):
```
show system interface <interface-name> | grep allowaccess
show user radius eduvpn-rsso
show user group eduvpn-vpn-users
```

Sniffer (non-invasive, confirms packets are received):
```
diagnose sniffer packet any "host <NAS-IP> and udp port 1813" 6 0 l
```
Expected output:
```
interfaces=[any]
filters=[host <NAS-IP> and udp port 1813]
2.634108 <NAS-IP>.XXXXX -> <FortiGate-IP>.1813: udp 92
2.634891 <FortiGate-IP>.1813 -> <NAS-IP>.XXXXX: udp 20
```
The second line (FortiGate's response) confirms `rsso-radius-response enable`
is working and the secret is correct. If only the first line appears, the
secret is wrong or the interface lacks `radius-acct`.

Live radiusd debug (filter visually for your NAS IP):
```
diagnose debug reset
diagnose debug application radiusd -1
diagnose debug enable
```
Expected for a correct Start:
```
radiusd: recv Accounting-Request from <NAS-IP>:XXXXX
radiusd:   User-Name = alice
radiusd:   Framed-IP-Address = 10.20.0.5
radiusd:   Framed-IPv6-Address = 2001:db8:1234:5678::5
radiusd:   Called-Station-Id = staff
radiusd:   Acct-Status-Type = Start
radiusd: add rsso user alice ip 10.20.0.5 group eduvpn-rsso
```
Disable right after testing: `diagnose debug disable && diagnose debug reset`.

RSSO database state:
```
diagnose test application radiusd 6    # summary, one line per entry
diagnose test application radiusd 66   # full detail, all attributes
```

Authenticated users, filtered by your VPN subnet:
```
diagnose firewall auth filter src 10.20.0.0/22
diagnose firewall auth list
diagnose firewall auth filter clear
```

Cleanup:
```
diagnose firewall auth delete <username>   # single user, other agents untouched
diagnose firewall auth clear               # ALL RSSO entries on the FortiGate — use with care
```

### Common errors

| Message | Cause | Fix |
|---|---|---|
| `bad authenticator` | Secret mismatch | Check `rsso-secret` matches `secret` in `eduvpn-radius.conf` |
| No debug output | Packets not arriving | Use the sniffer to confirm reception |
| `no rsso agent configured` | Agent not created | Do step 3 of Post-install |
| Only IPv4 added, not IPv6 | `Framed-IPv6-Address` missing from the packet | The daemon already includes it; check the test script includes both |
| Group empty in dashboard | `sso-attribute` not set | `set sso-attribute Called-Station-Id` |
| Entries don't disappear on disconnect | `rsso-flush-ip-session` disabled | `set rsso-flush-ip-session enable` |
| `RADIUS timeout` in the daemon log | FortiGate unreachable on UDP/1813 | Check `allowaccess radius-acct` on the interface |
| Log file not found at startup | Correlator not running | Start the correlator first; the daemon retries every 10s |

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
# then on FortiGate:
#   config user radius
#       edit "eduvpn-rsso"
#           set rsso-secret "<new-secret>"
#       next
#   end
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
