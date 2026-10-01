#!/usr/bin/env bash
# One-command installer for eduvpn-radius (FortiGate RSSO accounting daemon).
# Idempotent: safe to re-run. Never overwrites an existing configuration.
set -euo pipefail

LIBDIR=/usr/local/lib/eduvpn-radius
ETCDIR=/etc/eduvpn-radius
UNITS=/etc/systemd/system
CONF="$ETCDIR/eduvpn-radius.conf"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi

echo "==> Installing dependencies"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    apt-get install -y python3 python3-pyrad || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pyrad || true
fi
if ! python3 -c 'import pyrad' 2>/dev/null; then
    echo "WARN: no pyrad package — trying pip3 install pyrad" >&2
    pip3 install pyrad || true
fi
python3 -c 'import pyrad' 2>/dev/null || { echo "ERROR: Python module pyrad not available — install it, then re-run" >&2; exit 1; }

echo "==> Installing the daemon to $LIBDIR"
install -d -m 0755 "$LIBDIR"
install -m 0755 "$SRC/eduvpn-radius.py" "$LIBDIR/eduvpn-radius.py"
install -m 0644 "$SRC/dictionary" "$LIBDIR/dictionary"
rm -f "$LIBDIR/README.md"   # installed by older versions

echo "==> Installing the systemd unit to $UNITS"
# The unit is overwritten on re-run: customise it with `systemctl edit
# eduvpn-radius` (drop-ins survive), not by editing the file.
install -m 0644 "$SRC/systemd/eduvpn-radius.service" "$UNITS/eduvpn-radius.service"
systemctl daemon-reload

install -d -m 0750 "$ETCDIR"
if [ -f "$CONF" ]; then
    echo "==> Keeping the existing configuration $CONF"
    systemctl enable eduvpn-radius.service
    # restart, not just start: on an upgrade the old code must not keep running
    systemctl restart eduvpn-radius.service
    cat <<'EOF'

==> Done. eduvpn-radius restarted with the existing configuration:
  sudo journalctl -u eduvpn-radius -f
EOF
else
    install -m 0640 "$SRC/eduvpn-radius.conf.example" "$CONF"
    cat <<EOF

==> Done. The service is NOT started yet: $CONF is a template.

Remaining steps (see README, "Installation"):

1. Set the FortiGate address and the shared secret:
     sudo nano $CONF

2. Configure the RSSO agent on FortiGate with the same secret.

3. Check the path end to end, then start the daemon:
     sudo $LIBDIR/eduvpn-radius.py --test <unused IP of the VPN pool>
     sudo systemctl enable --now eduvpn-radius.service
EOF
fi
