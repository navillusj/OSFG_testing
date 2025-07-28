#!/bin/bash

# --- Configuration ---
DOMAIN_FILE="/var/www/html/blocked_domains.txt" # IMPORTANT: Ensure this path is correct and the file exists.
IPSET_NAME="blocked_sites"

# --- Pre-requisites Check ---

# Check if dig is installed
if ! command -v dig &> /dev/null; then
    echo "Error: 'dig' command not found. Please install dnsutils (e.g., sudo apt-get install dnsutils)." >&2
    exit 1
fi

# Check if ipset is installed
if ! command -v ipset &> /dev/null; then
    echo "Error: 'ipset' command not found. Please install ipset (e.g., sudo apt-get install ipset)." >&2
    exit 1
fi

# Check if DOMAIN_FILE exists
if [ ! -f "$DOMAIN_FILE" ]; then
    echo "Error: Domain file not found at '$DOMAIN_FILE'." >&2
    echo "Please ensure the file exists and contains domains to block, one per line." >&2
    exit 1
fi

echo "--- Starting IPset Update for '$IPSET_NAME' ---"

# --- 1. Destroy and Recreate the IPset ---
# Destroying and recreating ensures that old, no-longer-blocked IPs are removed.
echo "Destroying existing ipset '$IPSET_NAME' (if it exists) to ensure a clean slate..."
sudo ipset destroy "$IPSET_NAME" 2>/dev/null

echo "Creating ipset '$IPSET_NAME' (hash:ip type with 1024 hashsize, max 65536 elements)..."
sudo ipset create "$IPSET_NAME" hash:ip hashsize 1024 maxelem 65536 || {
    echo "Error: Failed to create ipset '$IPSET_NAME'." >&2
    echo "Please check ipset installation and permissions." >&2
    exit 1
}

# --- 2. Populate the IPset from the Domain File ---
echo "Populating ipset '$IPSET_NAME' from '$DOMAIN_FILE'..."
NUM_ADDED_IPS=0
NUM_DOMAINS_PROCESSED=0

while IFS= read -r domain; do
    # Trim whitespace and ignore empty lines or lines starting with '#' (comments)
    domain=$(echo "$domain" | xargs)
    if [[ -z "$domain" || "$domain" == \#* ]]; then
        continue # Skip empty lines or comments
    fi

    NUM_DOMAINS_PROCESSED=$((NUM_DOMAINS_PROCESSED + 1))
    echo "Resolving domain $NUM_DOMAINS_PROCESSED: $domain..."

    # Use dig to get IPv4 addresses only
    # grep -oE filters for valid IPv4 addresses
    ips=$(dig +short "$domain" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')

    if [ -z "$ips" ]; then
        echo "  Warning: No IPv4 addresses resolved for '$domain'." >&2
        continue
    fi

    for ip in $ips; do
        if [[ ! -z "$ip" ]]; then
            sudo ipset add "$IPSET_NAME" "$ip" || {
                echo "  Warning: Failed to add $ip to $IPSET_NAME. This might happen if the IP is already in the set or due to permissions." >&2
            }
            NUM_ADDED_IPS=$((NUM_ADDED_IPS + 1))
            # Uncomment for verbose output during testing:
            # echo "    Added $ip"
        fi
    done
done < "$DOMAIN_FILE"

echo "--- IPset Update Complete ---"
echo "Processed $NUM_DOMAINS_PROCESSED domains from '$DOMAIN_FILE'."
echo "Added $NUM_ADDED_IPS unique IPv4 addresses to '$IPSET_NAME'."
echo "Current IPs in $IPSET_NAME:"
sudo ipset list "$IPSET_NAME"

