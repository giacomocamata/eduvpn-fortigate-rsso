#!/usr/bin/env bash
# One-command installer for eduvpn-radius (FortiGate RSSO accounting daemon).
# Idempotent: safe to re-run. Never overwrites an already-configured conf file.
set -euo pipefail

LIBDIR=/usr/local/lib/eduvpn-radius
ETCDIR=/etc/eduvpn-radius
STATEDIR=/var/lib/eduvpn-radius
UNITS=/etc/systemd/system
CONF="$ETCDIR/eduvpn-radius.conf"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi

echo "==> Installing dependencies"
PYRAD_OK=0
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    if apt-get install -y python3-pyrad; then
        PYRAD_OK=1
    fi
elif command -v dnf >/dev/null 2>&1; then
    if dnf install -y python3-pyrad; then
        PYRAD_OK=1
    fi
else
    echo "WARN: no apt/dnf found — install pyrad manually (pip3 install pyrad)" >&2
fi

if [ "$PYRAD_OK" -ne 1 ]; then
    echo "WARN: distro package for pyrad unavailable — falling back to pip3 install pyrad" >&2
    pip3 install pyrad || echo "WARN: pip3 install pyrad failed — install it manually before starting the service" >&2
fi

echo "==> Installing daemon files to $LIBDIR"
mkdir -p "$LIBDIR"
install -m 0755 "$SRC/eduvpn-radius.py" "$LIBDIR/eduvpn-radius.py"
install -m 0644 "$SRC/dictionary" "$LIBDIR/dictionary"
install -m 0644 "$SRC/README.md" "$LIBDIR/README.md"

echo "==> Installing systemd unit to $UNITS"
install -m 0644 "$SRC/systemd/eduvpn-radius.service" "$UNITS/eduvpn-radius.service"

echo "==> Creating runtime directories"
mkdir -p "$ETCDIR" "$STATEDIR"

CONF_EXISTED=0
if [ -f "$CONF" ]; then
    CONF_EXISTED=1
    echo "==> Existing configuration found at $CONF — leaving it untouched"
else
    echo "==> No configuration found — installing example template"
    install -m 0640 "$SRC/eduvpn-radius.conf.example" "$CONF"
fi

echo "==> Reloading systemd"
systemctl daemon-reload

if [ "$CONF_EXISTED" -eq 1 ]; then
    echo "==> Existing configuration detected — enabling and (re)starting the service"
    systemctl enable --now eduvpn-radius.service
else
    echo "==> Fresh install — service NOT started (placeholder configuration would fail)"
fi

cat <<'EOF'

==> Done.

NEXT STEPS:
EOF

if [ "$CONF_EXISTED" -eq 0 ]; then
cat <<EOF
1. Edit $CONF — set the real FortiGate address and shared secret:
     sudo nano $CONF
   (mode is already 640; keep the secret non-world-readable)

2. Configure the RSSO agent on the FortiGate side — see README.md,
   "Post-install steps" section.

3. Start the daemon once configured:
     sudo systemctl enable --now eduvpn-radius.service
     sudo journalctl -u eduvpn-radius -f
EOF
else
cat <<'EOF'
Configuration already present — service (re)started with the existing config.
Check status with:
  sudo systemctl status eduvpn-radius.service
  sudo journalctl -u eduvpn-radius -f
EOF
fi
