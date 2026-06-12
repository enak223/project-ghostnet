#!/usr/bin/env bash
# GhostNet — Suricata + ET Open Rules Install
# Usage: bash install_suricata.sh [interface]
set -euo pipefail

IFACE="${1:-ens33}"
LOG_DIR="/var/log/suricata"

echo "[*] Installing Suricata..."
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update -qq
sudo apt-get install -y suricata suricata-update jq

echo "[*] Enabling ET Open ruleset..."
sudo suricata-update update-sources
sudo suricata-update enable-source et/open
sudo suricata-update

echo "[*] Patching HOME_NET and interface in suricata.yaml..."
sudo sed -i 's|HOME_NET:.*|HOME_NET: "[192.168.248.0/24]"|' /etc/suricata/suricata.yaml
sudo sed -i "s|interface: eth0|interface: $IFACE|g" /etc/suricata/suricata.yaml
sudo sed -i "s|interface: default|interface: $IFACE|g" /etc/suricata/suricata.yaml

echo "[*] Enabling EVE JSON output (verify 'outputs' section manually if needed)..."

sudo mkdir -p "$LOG_DIR"
sudo chown suricata:suricata "$LOG_DIR" 2>/dev/null || true

echo "[*] Enabling and starting Suricata..."
sudo systemctl enable suricata
sudo systemctl restart suricata
sleep 4
sudo systemctl status suricata --no-pager | head -15

echo ""
if [ -f "$LOG_DIR/eve.json" ]; then
    echo "[+] eve.json exists — Suricata writing alerts."
else
    echo "[!] eve.json not yet created — needs traffic or a moment to start."
fi

echo ""
echo "=== Done. EVE log: $LOG_DIR/eve.json ==="
