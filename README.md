# eduvpn-fortigate-rsso

*🇮🇹 [Leggi in italiano](README.it.md)*

**User identity for [eduVPN](https://www.eduvpn.org/) WireGuard sessions on a FortiGate, through RADIUS Accounting (RSSO).**

When an eduVPN server forwards client traffic to a FortiGate without NAT, the
FortiGate sees the tunnel address of every client (e.g. `10.20.0.5`) but not the
user behind it: its logs and policies can only work by address pool. FortiGate's
**RADIUS Single Sign-On (RSSO)** fills that gap: it learns *user ↔ IP* pairs from
standard RADIUS Accounting-Start/Stop packets (RFC 2866) sent by a NAS.

`eduvpn-radius` is that NAS. It follows the session log written by
[eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger) and turns every
`connect` into an Accounting-Start and every `disconnect` into the matching
Accounting-Stop:

```
eduvpn.log   2026-04-15T09:58:03.412871+02:00 event=connect user=alice profile=staff device=ios conn=soAQTNO...= tunnel_ip4="10.20.0.5" tunnel_ip6="fd00:20::5" ...
  →  Accounting-Start  User-Name=alice  Framed-IP-Address=10.20.0.5  Framed-IPv6-Address=fd00:20::5  Called-Station-Id=staff  Acct-Session-Id=3f9c0a1be47d2c55

eduvpn.log   2026-04-15T11:02:57.731204+02:00 event=disconnect user=alice profile=staff device=ios conn=soAQTNO...= ...
  →  Accounting-Stop   User-Name=alice  Framed-IP-Address=10.20.0.5  Framed-IPv6-Address=fd00:20::5  Called-Station-Id=staff  Acct-Session-Id=3f9c0a1be47d2c55
```

A single-file Python daemon (standard library + `pyrad`), running in production
at the University of Trieste next to eduvpn-logger.

## How it works

Sessions are tracked by **WireGuard public key** (`conn`), the key eduvpn-logger
uses too:

| Log event | RADIUS | Notes |
|---|---|---|
| `connect` | Accounting-Start | new session id; the same session announced again (eduvpn-logger does it after its own restart) re-sends the Start with the same id, without a Stop |
| `connect`, same key, new tunnel IP | Stop, then Start | the old session is closed first |
| `connect` with a tunnel IP held by another session | Stop for the other, then Start | the pool reassigned the address, so the other session's disconnect was missed and it is over |
| `disconnect` | Accounting-Stop | same `Acct-Session-Id` as the Start |
| `roam` | none | the tunnel IP does not change, only the public source address |
| `connect` with `user=-` or without tunnel IP | none | nothing FortiGate could use |

The daemon keeps its sessions and the position reached in the log in
`/var/lib/eduvpn-radius/state.json`:

- **Restarts.** On stop it sends an Accounting-Stop for every open session, so
  FortiGate never keeps a stale *user ↔ IP* pair while nobody updates it. On
  start it first reads what was logged while it was down (also across a log
  rotation), then re-sends the Accounting-Start for the sessions still open,
  with their original session ids.
- **FortiGate unreachable.** A Start that gets no answer is retried every 30 s
  until FortiGate replies. Stops are not retried (see [Limitations](#limitations)).
- **Log rotation.** Both `create` and `copytruncate` rotations are followed by
  name, and no line written around a rotation is skipped.

## Requirements

- An eduVPN server with **[eduvpn-logger](https://github.com/giacomocamata/eduvpn-logger)**
  installed and running (or another tool writing the same `event=` lines to
  `/var/log/eduvpn/eduvpn.log`).
- systemd-based Linux, Python ≥ 3.9 and [`pyrad`](https://github.com/pyradius/pyrad)
  (`python3-pyrad` on Debian/Ubuntu, installed by `install.sh`).
- A FortiGate with RSSO, reachable on UDP 1813 from the eduVPN server. Tested
  with FortiOS 7.4.
- A routed (No-NAT) setup: FortiGate must see the tunnel addresses as the source
  of client traffic, or the mapping has nothing to match.

## Installation

### 1. eduvpn-logger

Install eduvpn-logger and check that `connect` lines with the user and the
tunnel IPs appear in `/var/log/eduvpn/eduvpn.log` when a client connects.
eduvpn-radius only reads that file.

### 2. Install the daemon

```bash
git clone https://github.com/giacomocamata/eduvpn-fortigate-rsso.git
cd eduvpn-fortigate-rsso
sudo ./install.sh
```

`install.sh` is idempotent and does the following:

| Item | Path |
|---|---|
| packages | `python3`, `python3-pyrad` (pip fallback if the package is missing) |
| program | `/usr/local/lib/eduvpn-radius/eduvpn-radius.py` and its RADIUS `dictionary` |
| systemd unit | `/etc/systemd/system/eduvpn-radius.service` |
| configuration | `/etc/eduvpn-radius/eduvpn-radius.conf`, `0640`, only if absent |
| state | `/var/lib/eduvpn-radius` (created by systemd, `0700`) |

On a first install the configuration is a template with placeholder values and
the service is **not** started. When a configuration already exists, it is
kept and the service is restarted.

<details>
<summary>Manual installation (without <code>install.sh</code>)</summary>

```bash
sudo apt install -y python3 python3-pyrad      # dnf on Fedora/EL
sudo install -d -m 0755 /usr/local/lib/eduvpn-radius
sudo install -m 0755 eduvpn-radius.py /usr/local/lib/eduvpn-radius/
sudo install -m 0644 dictionary /usr/local/lib/eduvpn-radius/
sudo install -m 0644 systemd/eduvpn-radius.service /etc/systemd/system/
sudo install -d -m 0750 /etc/eduvpn-radius
sudo install -m 0640 eduvpn-radius.conf.example /etc/eduvpn-radius/eduvpn-radius.conf
sudo systemctl daemon-reload
```

</details>

### 3. Configure

```bash
sudo nano /etc/eduvpn-radius/eduvpn-radius.conf
```

Set `server` to the FortiGate address the RADIUS packets should go to and
`secret` to a new random value (`openssl rand -base64 24`). The daemon refuses to
start while the secret is still the placeholder. All keys are described in
[Configuration](#configuration).

### 4. Configure FortiGate

The FortiGate side is configured on the FortiGate itself, with RSSO. The menus
and commands change between FortiOS releases, so they are not repeated here.
Conceptually, four things are needed:

1. **RADIUS accounting accepted** on the interface facing the eduVPN server, on
   the configured port (UDP 1813 by default).
2. **An RSSO agent** with the same shared secret as `eduvpn-radius.conf`, set to
   read the client address from `Framed-IP-Address` and the group from
   `Called-Station-Id` (see [RADIUS attributes](#radius-attributes)).
3. **An RSSO user group** that refers to that agent.
4. **Firewall policies** for the VPN address pools that use that group, so their
   logs carry the user name. The group can also be used to filter access.

See Fortinet's documentation for your FortiOS version, e.g.
[Configuring RADIUS SSO authentication](https://docs.fortinet.com/document/fortigate/7.6.2/administration-guide/513092/configuring-radius-sso-authentication)
in the [Fortinet Document Library](https://docs.fortinet.com/).

### 5. Verify

First check the path to FortiGate with a test session: use an address of the
VPN pool that is not in use.

```bash
sudo /usr/local/lib/eduvpn-radius/eduvpn-radius.py --test 10.20.0.250
```

It sends an Accounting-Start for the user `eduvpn-radius-test`, waits for ENTER
(check now that the user appears in FortiGate's RSSO user list), then sends the
Accounting-Stop. Then start the service and connect a client:

```bash
sudo systemctl enable --now eduvpn-radius.service
sudo journalctl -u eduvpn-radius -f
```

Each session produces a `start(connect) user=… ok=True` line and later a
`stop(disconnect) … ok=True` line. `ok=True` means FortiGate answered.

| Symptom | Likely cause |
|---|---|
| `secret is not set (still the placeholder?)`, service failed | step 3 not done |
| `RADIUS timeout`, `ok=False` | FortiGate not reachable on UDP 1813 from this host, accounting not accepted on that interface, or **different shared secret** (FortiGate silently drops packets with a wrong secret) |
| `ok=True` but no user on FortiGate | RSSO agent attribute settings (`Framed-IP-Address`, `Called-Station-Id`) |
| user listed but policies/logs without it | policy does not use the RSSO group, or traffic is NATed before the FortiGate |
| no `start` lines at all | eduvpn-logger not writing connects (step 1), or `log_path` wrong |
| `connect without tunnel IP ignored` | eduvpn-logger could not determine the tunnel address of that session |

## Configuration

`/etc/eduvpn-radius/eduvpn-radius.conf` (INI). After a change:
`sudo systemctl restart eduvpn-radius.service`.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[radius]` | `server` | *(required)* | FortiGate address (IP or host name) |
| `[radius]` | `port` | `1813` | RADIUS accounting port |
| `[radius]` | `secret` | *(required)* | shared secret, the same as the FortiGate RSSO agent |
| `[radius]` | `nas_identifier` | host name | `NAS-Identifier` of every packet |
| `[eduvpn]` | `log_path` | `/var/log/eduvpn/eduvpn.log` | log written by eduvpn-logger |
| `[eduvpn]` | `state_path` | `/var/lib/eduvpn-radius/state.json` | open sessions and log position |

The unit file itself is replaced on re-install. To change it (e.g. a different
config path), use a drop-in: `sudo systemctl edit eduvpn-radius.service`.

## RADIUS attributes

Every packet is an Accounting-Request (UDP, default port 1813) with:

| Attribute | Value |
|---|---|
| `Acct-Status-Type` | `Start` (1) or `Stop` (2) |
| `User-Name` | eduVPN user ID, as written by eduvpn-logger |
| `Framed-IP-Address` | tunnel IPv4 address, if any |
| `Framed-IPv6-Address` | tunnel IPv6 address, if any (RFC 6911) |
| `Called-Station-Id` | eduVPN profile ID, usable as RSSO group |
| `Acct-Session-Id` | 16 hex characters, the same in a session's Start and Stop |
| `NAS-Identifier` | `nas_identifier`, by default the host name |
| `Acct-Delay-Time` | only on retransmissions (added by pyrad) |

Each packet is sent up to twice, waiting 5 s for FortiGate's
Accounting-Response; without one the daemon logs `ok=False`.

## Limitations

- **The mapping is as accurate as eduvpn-logger.** Sessions it closes after 180 s
  of handshake silence (inferred disconnects) leave FortiGate up to 3 minutes
  later than the actual end of the tunnel.
- **Stops are not retried.** A Stop lost while FortiGate is unreachable leaves
  the pair on FortiGate until the address is assigned again (the new Start
  replaces it) or the entry expires on FortiGate.
- **A FortiGate reboot** empties its RSSO table; the open sessions come back at
  the next connect or with `systemctl restart eduvpn-radius`.
- **While the daemon is stopped** FortiGate has no pairs for VPN users; on start
  the backlog is replayed. A downtime spanning more than one log rotation loses
  the events of the older, already compressed file.
- **First start.** Sessions that were already open when the daemon is started
  for the first time are not known until they reconnect.

## Security and privacy

- **Shared secret.** The configuration is `0640 root:root` in a `0750` directory.
  RADIUS accounting is not encrypted: the user names travel in clear text to
  FortiGate, so keep that path on a trusted network.
- **Personal data.** The state file holds user IDs and their tunnel addresses
  (`0700` directory). FortiGate logs will associate traffic with users: define
  purpose and retention with your Data Protection Officer.
- **Privileges.** The service runs as root inside a systemd sandbox, with no
  capabilities, only IPv4/IPv6/Unix sockets and a read-only `/usr`, `/boot` and
  `/etc`. Inspect with `systemd-analyze security eduvpn-radius.service`.

## Upgrade and removal

Upgrade (configuration and state are kept; the service is restarted):

```bash
cd eduvpn-fortigate-rsso && git pull && sudo ./install.sh
```

The state file of earlier versions is read as is.

Removal:

```bash
sudo systemctl disable --now eduvpn-radius.service
sudo rm -rf /usr/local/lib/eduvpn-radius /etc/eduvpn-radius /var/lib/eduvpn-radius \
    /etc/systemd/system/eduvpn-radius.service /etc/systemd/system/eduvpn-radius.service.d
sudo systemctl daemon-reload
```

Then remove the RSSO agent, group and policy references on FortiGate.

## License

MIT, see [LICENSE](LICENSE).
