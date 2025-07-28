#!/bin/bash
NEW_SSID="$1"
NEW_PASS="$2"
HOSTAPD_CONF="/etc/hostapd/hostapd.conf"

if [[ -z "$NEW_SSID" || -z "$NEW_PASS" ]]; then
    echo "Error: SSID and password must be provided." >&2
    exit 1
fi

if ! command -v sed &>/dev/null; then
    echo "Error: 'sed' command not found." >&2
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    echo "Error: 'systemctl' command not found." >&2
    exit 1
fi

if ! [ -f "$HOSTAPD_CONF" ]; then
    echo "Error: hostapd configuration file not found at $HOSTAPD_CONF." >&2
    exit 1
fi

sudo sed -i "s/^ssid=.*/ssid=$NEW_SSID/" "$HOSTAPD_CONF"
sudo sed -i "s/^wpa_passphrase=.*/wpa_passphrase=$NEW_PASS/" "$HOSTAPD_CONF"

sudo systemctl restart hostapd

if [ $? -eq 0 ]; then
    echo "hostapd configuration updated and service restarted successfully."
    exit 0
else
    echo "Error: Failed to restart hostapd service." >&2
    exit 1
fi
