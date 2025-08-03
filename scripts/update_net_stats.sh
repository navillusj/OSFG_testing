#!/bin/bash
# set -x # <-- IMPORTANT: Uncomment this line (remove the '#') if you need verbose debugging output.
#    It will show every command executed by the script, which is invaluable for troubleshooting.
#    Remember to comment it out after successful debugging to reduce log verbosity.

# --- Configuration ---
# File to store the network statistics in JSON format for the PHP webpage to read.
# Ensure this directory exists and is writable by the user running this script (root via sudo/cron),
# and readable by your web server user (e.g., www-data).
# Suggested setup:
#   sudo mkdir -p /var/log/
#   sudo touch /var/log/network_stats.json
#   sudo chown root:www-data /var/log/network_stats.json
#   sudo chmod 640 /var/log/network_stats.json
STATS_FILE="/var/log/network_stats.json" # <--- IMPORTANT: Verify/Change this path if needed!

# File to store previous statistics (cumulative bytes and timestamp) for delta calculation.
# This is a temporary file used internally by the script.
# Ensure /tmp is writable by the user running this script (usually root via cron).
PREV_STATS_FILE="/tmp/network_stats_prev.json"

# The network interface to monitor (e.g., eth0, ens33, enp0s3, br0).
# Run `ip a` on your server to confirm the exact name of your primary internet-facing interface.
# For a router setup, 'br0' is commonly the bridged interface connected to your LAN/WAN.
INTERFACE="br0" # <--- IMPORTANT: Verify this is your actual network interface!

# --- Function to check if 'jq' is installed ---
check_jq() {
    if ! command -v jq &> /dev/null; then
        echo "$(date): Error: 'jq' command not found. Please install jq." >&2
        echo "$(date):   For Debian/Ubuntu: sudo apt update && sudo apt install jq" >&2
        echo "$(date):   For CentOS/RHEL/Fedora: sudo yum install jq or sudo dnf install jq" >&2
        exit 1
    fi
}

# --- Helper function to get total interface stats (RX_bytes TX_bytes) ---
# Reads network statistics directly from the Linux kernel's sysfs filesystem.
get_interface_stats() {
    RX_FILE="/sys/class/net/$INTERFACE/statistics/rx_bytes"
    TX_FILE="/sys/class/net/$INTERFACE/statistics/tx_bytes"

    if [ ! -d "/sys/class/net/$INTERFACE" ]; then
        echo "$(date): Error: Interface directory /sys/class/net/$INTERFACE does not exist." >&2
        echo "$(date): Please verify INTERFACE name: '$INTERFACE' with 'ip a' command." >2
        return 1
    fi
    if [ ! -f "$RX_FILE" ] || [ ! -f "$TX_FILE" ]; then
        echo "$(date): Error: Stats files missing for $INTERFACE. Expected: '$RX_FILE' and '$TX_FILE'" >&2
        echo "$(date): Interface might not be fully configured or active for statistics." >2
        return 1
    fi

    CURRENT_RX_BYTES=$(cat "$RX_FILE" 2>/dev/null)
    CURRENT_TX_BYTES=$(cat "$TX_FILE" 2>/dev/null)

    if [[ -z "$CURRENT_RX_BYTES" || -z "$CURRENT_TX_BYTES" || \
          ! "$CURRENT_RX_BYTES" =~ ^[0-9]+$ || ! "$CURRENT_TX_BYTES" =~ ^[0-9]+$ ]]; then
        echo "$(date): Error: Failed to read numeric RX/TX bytes from sysfs files." >&2
        echo "$(date): RX_FILE: '$RX_FILE' content: '$CURRENT_RX_BYTES'" >&2
        echo "$(date): TX_FILE: '$TX_FILE' content: '$CURRENT_TX_BYTES'" >&2
        return 1
    fi

    echo "$CURRENT_RX_BYTES $CURRENT_TX_BYTES"
}

# --- Main Script Logic ---
check_jq
echo "$(date): Starting network statistics collection for $INTERFACE..."

READ_STATS_OUTPUT=$(get_interface_stats)
if [ $? -ne 0 ]; then
    echo "$(date): Script failed to get interface statistics. Exiting." >&2
    exit 1
fi

CURRENT_RX_BYTES=$(echo "$READ_STATS_OUTPUT" | awk '{print $1}')
CURRENT_TX_BYTES=$(echo "$READ_STATS_OUTPUT" | awk '{print $2}')
CURRENT_TIMESTAMP=$(date +%s)

# Read previous stats from PREV_STATS_FILE.
# 'jq -r .key // 0' safely extracts values, defaulting to 0 if key is missing or null.
PREV_RX_BYTES=0
PREV_TX_BYTES=0
PREV_TIMESTAMP=0 # Initialize to prevent issues if file is missing

if [ -f "$PREV_STATS_FILE" ] && [ -s "$PREV_STATS_FILE" ]; then # Check if file exists AND is not empty
    PREV_STATS_JSON=$(cat "$PREV_STATS_FILE" 2>/dev/null)
    if [ $? -eq 0 ] && echo "$PREV_STATS_JSON" | jq -e . >/dev/null 2>&1; then # Check if jq parses successfully
        PREV_RX_BYTES=$(echo "$PREV_STATS_JSON" | jq -r '.rx_bytes // 0')
        PREV_TX_BYTES=$(echo "$PREV_STATS_JSON" | jq -r '.tx_bytes // 0')
        PREV_TIMESTAMP=$(echo "$PREV_STATS_JSON" | jq -r '.timestamp // 0')
    else
        echo "$(date): Warning: '$PREV_STATS_FILE' exists but is unreadable or invalid JSON. Initializing deltas to 0." >&2
    fi
else
    echo "$(date): Previous stats file '$PREV_STATS_FILE' not found or empty. Initializing with zero deltas." >&2
fi

DELTA_RX_BYTES=$((CURRENT_RX_BYTES - PREV_RX_BYTES))
DELTA_TX_BYTES=$((CURRENT_TX_BYTES - PREV_TX_BYTES))

# Handle reboot or counter reset (e.g., if interface was reset, counter goes back to 0).
# If current is less than previous, it's a reset. Use current cumulative as delta for this interval.
if (( DELTA_RX_BYTES < 0 || PREV_TIMESTAMP == 0 || CURRENT_TIMESTAMP - PREV_TIMESTAMP > 3600 )); then # If delta is negative, or first run, or large time gap (e.g., reboot after a long time)
    echo "$(date): Detected potential RX counter reset or first run. Delta set to current RX: $CURRENT_RX_BYTES." >&2
    DELTA_RX_BYTES=$CURRENT_RX_BYTES
fi
if (( DELTA_TX_BYTES < 0 || PREV_TIMESTAMP == 0 || CURRENT_TIMESTAMP - PREV_TIMESTAMP > 3600 )); then
    echo "$(date): Detected potential TX counter reset or first run. Delta set to current TX: $CURRENT_TX_BYTES." >&2
    DELTA_TX_BYTES=$CURRENT_TX_BYTES
fi

# Store the current timestamp and bytes for the next run's delta calculation.
# This should happen regardless of counter resets for accurate future deltas.
CURRENT_SNAPSHOT_JSON=$(jq -n \
                        --argjson current_rx_bytes "$CURRENT_RX_BYTES" \
                        --argjson current_tx_bytes "$CURRENT_TX_BYTES" \
                        --argjson timestamp "$CURRENT_TIMESTAMP" \
                        '{rx_bytes: $current_rx_bytes, tx_bytes: $current_tx_bytes, timestamp: $timestamp}')

echo "$CURRENT_SNAPSHOT_JSON" > "$PREV_STATS_FILE" || \
{ echo "$(date): Error: Failed to write current snapshot to '$PREV_STATS_FILE'. Check permissions or disk space." >&2; }

# --- Placeholder for "Top User" / "Top IP" information ---
TOP_IPS_INFO="N/A (Requires advanced setup: e.g., iptables accounting, NetFlow/sFlow, or nethogs. These tools need regular parsing and potentially DB storage for historical user tracking. Current script collects interface totals only.)"

# Create the full JSON output for the PHP webpage.
FINAL_JSON_OUTPUT=$(jq -n \
              --arg iface "$INTERFACE" \
              --argjson current_rx_bytes "$CURRENT_RX_BYTES" \
              --argjson current_tx_bytes "$CURRENT_TX_BYTES" \
              --argjson delta_rx_bytes "$DELTA_RX_BYTES" \
              --argjson delta_tx_bytes "$DELTA_TX_BYTES" \
              --argjson timestamp "$CURRENT_TIMESTAMP" \
              --arg top_ips_info "$TOP_IPS_INFO" \
              '{
                  "interface": $iface,
                  "current_rx_bytes": $current_rx_bytes,
                  "current_tx_bytes": $current_tx_bytes,
                  "delta_rx_bytes": $delta_rx_bytes,
                  "delta_tx_bytes": $delta_tx_bytes,
                  "timestamp": $timestamp,
                  "top_ips_info": $top_ips_info
              }')

# Save the final JSON output to the main STATS_FILE.
echo "$FINAL_JSON_OUTPUT" > "$STATS_FILE" || \
{ echo "$(date): Error: Failed to write to STATS_FILE: '$STATS_FILE'. Check permissions or disk space." >&2; exit 1; }

# Set permissions for the STATS_FILE so the web server can read it.
# 'www-data' is common for Apache on Debian/Ubuntu. Adjust if your web server uses a different user/group.
sudo chown root:www-data "$STATS_FILE" || echo "$(date): Warning: Failed to chown '$STATS_FILE'. Check sudo permissions or user/group." >&2
sudo chmod 640 "$STATS_FILE" || echo "$(date): Warning: Failed to chmod '$STATS_FILE'. Check sudo permissions." >&2

echo "$(date): Network statistics collection for $INTERFACE completed and saved to '$STATS_FILE'."

# --- CRON JOB REMINDER ---
# To make this script run automatically, add it to cron.
# Run 'sudo crontab -e' and add a line like:
# */5 * * * * /usr/local/bin/update_net_stats.sh > /dev/null 2>&1
# This will run the script every 5 minutes. Adjust frequency as needed.
# Ensure the script path is correct.
