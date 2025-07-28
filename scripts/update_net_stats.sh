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
STATS_FILE="/var/log/network_stats.json" # <--- IMPORTANT: Verify/Change this path if needed!
# File to store previous statistics (cumulative bytes and timestamp) for delta calculation.
# This is a temporary file used internally by the script to calculate upload/download amounts
# between each script run.
PREV_STATS_FILE="/tmp/network_stats_prev.json"

# The network interface to monitor (e.g., eth0, ens33, enp0s3, br0).
# Run `ip a` on your server to confirm the exact name of your primary internet-facing interface.
# Based on your previous output, 'br0' is the correct interface name for your setup.
INTERFACE="br0" # <--- IMPORTANT: Verify this is your actual network interface!
# --- Function to check if 'jq' is installed ---
# 'jq' is a command-line JSON processor and is essential for creating and parsing the JSON data.
check_jq() {
    if ! command -v jq &> /dev/null; then
        echo "$(date): Error: 'jq' command not found. Please install jq." >&2
        echo "$(date):   For Debian/Ubuntu: sudo apt update && sudo apt install jq" >&2
        echo "$(date):   For CentOS/RHEL/Fedora: sudo yum install jq or sudo dnf install jq" >&2
        exit 1
    fi
}

# --- Helper function to get total interface stats (RX_bytes TX_bytes) ---
# This function reads network statistics directly from the Linux kernel's sysfs filesystem.
# This is the most robust method as it avoids parsing complex command output and
# is less susceptible to variations in command-line utility versions or locales.
get_interface_stats() {
    RX_FILE="/sys/class/net/$INTERFACE/statistics/rx_bytes" # Path to received bytes file
    TX_FILE="/sys/class/net/$INTERFACE/statistics/tx_bytes" # Path to transmitted bytes file

    # Check if the interface directory and stats files exist.
    # This ensures the interface is recognized and sysfs is exporting its statistics.
    if [ ! -d "/sys/class/net/$INTERFACE" ]; then
        echo "$(date): Error: Interface directory /sys/class/net/$INTERFACE does not exist." >&2
        echo "$(date): Please verify INTERFACE name: '$INTERFACE' with 'ip a' command." >&2
        return 1 # Indicate failure
    fi
    if [ ! -f "$RX_FILE" ] || [ ! -f "$TX_FILE" ]; then
        echo "$(date): Error: Stats files missing for $INTERFACE. Expected: '$RX_FILE' and '$TX_FILE'" >&2
        echo "$(date): Interface might not be fully configured or active for statistics." >&2
        return 1 # Indicate failure
    fi

    # Read the byte counts directly from the sysfs files using 'cat'.
    # '2>/dev/null' suppresses any potential error messages from 'cat' if files are briefly unreadable.
    CURRENT_RX_BYTES=$(cat "$RX_FILE" 2>/dev/null)
    CURRENT_TX_BYTES=$(cat "$TX_FILE" 2>/dev/null)

    # Basic validation: ensure the values read are not empty and are purely numeric.
    if [[ -z "$CURRENT_RX_BYTES" || -z "$CURRENT_TX_BYTES" || \
          ! "$CURRENT_RX_BYTES" =~ ^[0-9]+$ || ! "$CURRENT_TX_BYTES" =~ ^[0-9]+$ ]]; then
        echo "$(date): Error: Failed to read numeric RX/TX bytes from sysfs files." >&2
        echo "$(date): RX_FILE: '$RX_FILE' content: '$CURRENT_RX_BYTES'" >&2
        echo "$(date): TX_FILE: '$TX_FILE' content: '$CURRENT_TX_BYTES'" >&2
        return 1 # Indicate parsing/reading failure
    fi

    # Print the successfully extracted bytes, space-separated.
    echo "$CURRENT_RX_BYTES $CURRENT_TX_BYTES"
}

# --- Main Script Logic ---
check_jq # Ensure 'jq' is installed and available before proceeding.
echo "$(date): Starting network statistics collection for $INTERFACE..."

# Get current bytes.
# If 'get_interface_stats' fails (returns non-zero exit code), exit the script.
READ_STATS_OUTPUT=$(get_interface_stats)
if [ $? -ne 0 ]; then
    echo "$(date): Script failed to get interface statistics. Exiting." >&2
    exit 1
fi

# Extract the RX and TX bytes from the output of get_interface_stats.
CURRENT_RX_BYTES=$(echo "$READ_STATS_OUTPUT" | awk '{print $1}')
CURRENT_TX_BYTES=$(echo "$READ_STATS_OUTPUT" | awk '{print $2}')
CURRENT_TIMESTAMP=$(date +%s) # Get current Unix timestamp (seconds since epoch).
# Read previous stats from PREV_STATS_FILE for delta calculation.
if [ -f "$PREV_STATS_FILE" ]; then
    PREV_STATS_JSON=$(cat "$PREV_STATS_FILE")
    # Use 'jq -r .key // 0' to safely extract values, defaulting to 0 if key is missing or null.
    PREV_RX_BYTES=$(echo "$PREV_STATS_JSON" | jq -r '.rx_bytes // 0')
    PREV_TX_BYTES=$(echo "$PREV_STATS_JSON" | jq -r '.tx_bytes // 0')
    PREV_TIMESTAMP=$(echo "$PREV_STATS_JSON" | jq -r '.timestamp // 0')
else
    # If the previous stats file doesn't exist or is empty, this is either the first run
    # or the file was cleared. Set previous bytes to 0 to make initial delta equal to current bytes.
    PREV_RX_BYTES=0
    PREV_TX_BYTES=0
    PREV_TIMESTAMP=$CURRENT_TIMESTAMP # Set to current timestamp to prevent huge initial delta.
    echo "$(date): Previous stats file '$PREV_STATS_FILE' not found or empty. Initializing with zero deltas." >&2
fi

# Calculate deltas (amount of bytes transferred since the last script run).
DELTA_RX_BYTES=$((CURRENT_RX_BYTES - PREV_RX_BYTES))
DELTA_TX_BYTES=$((CURRENT_TX_BYTES - PREV_TX_BYTES))

# Handle reboot or counter reset: If current bytes are less than previous bytes,
# it means the counter has reset (e.g., after a reboot). In this case, use the
# current cumulative bytes as the delta for this interval.
if (( DELTA_RX_BYTES < 0 )); then
    echo "$(date): Detected RX counter reset. Delta set to current RX: $CURRENT_RX_BYTES." >&2
    DELTA_RX_BYTES=$CURRENT_RX_BYTES
fi
if (( DELTA_TX_BYTES < 0 )); then
    echo "$(date): Detected TX counter reset. Delta set to current TX: $CURRENT_TX_BYTES." >&2
    DELTA_TX_BYTES=$CURRENT_TX_BYTES
fi

# --- Placeholder for "Top User" / "Top IP" information ---
# As discussed, accurately determining "Top User" by bandwidth consumed on a simple web page
# without specialized tools (like NetFlow collectors, deep packet inspection, or complex
# 'iptables' accounting rules that are regularly reset and parsed) is not feasible.
# This field serves as a placeholder to be expanded with more advanced monitoring if needed.
TOP_IPS_INFO="N/A (Requires advanced setup, e.g., iptables accounting or monitoring tools)"

# Create the full JSON output to be read by the PHP webpage.
JSON_OUTPUT=$(jq -n \
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

# Save only the cumulative bytes and timestamp to PREV_STATS_FILE.
# This temporary file is used by the script on its next run to calculate the deltas.
echo "$JSON_OUTPUT" | jq -r '{rx_bytes: .current_rx_bytes, tx_bytes: .current_tx_bytes, timestamp: .timestamp}' > "$PREV_STATS_FILE" || \
{ echo "$(date): Error: Failed to write to PREV_STATS_FILE: '$PREV_STATS_FILE'. Check permissions or disk space." >&2; }

# Save the full JSON output to the main STATS_FILE. This is the file the PHP page reads.
echo "$JSON_OUTPUT" > "$STATS_FILE" || \
{ echo "$(date): Error: Failed to write to STATS_FILE: '$STATS_FILE'. Check permissions or disk space." >&2; exit 1; }

# Set permissions for the STATS_FILE so the web server can read it.
# Adjust 'www-data' to your web server group if different (e.g., 'apache' for CentOS/RHEL).
sudo chown root:www-data "$STATS_FILE" || echo "$(date): Warning: Failed to chown '$STATS_FILE'. Check sudo permissions or user/group." >&2
sudo chmod 640 "$STATS_FILE" || echo "$(date): Warning: Failed to chmod '$STATS_FILE'. Check sudo permissions." >&2

echo "$(date): Network statistics collection for $INTERFACE completed and saved to '$STATS_FILE'."
