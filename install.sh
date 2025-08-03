#!/bin/bash

# --- 1. CONFIGURATION (User Input) ---
# --- Pre-installation checks and configuration prompts ---

# Function to get a valid number choice from the user
get_choice() {
    local prompt_text="$1"
    local default_choice="$2"
    local max_choice="$3"
    local choice_var_name="$4"
    local user_input
    
    if [[ -n "$default_choice" && "$default_choice" -le "$max_choice" ]]; then
        read -rp "$prompt_text (Default: $default_choice): " user_input
        if [[ -z "$user_input" ]]; then
            eval "$choice_var_name=$default_choice"
            echo "Using default choice: $default_choice"
            return 0
        fi
    else
        read -rp "$prompt_text: " user_input
    fi

    if [[ "$user_input" =~ ^[0-9]+$ && "$user_input" -ge 1 && "$user_input" -le "$max_choice" ]]; then
        eval "$choice_var_name=$user_input"
        return 0
    else
        echo "Invalid input. Please enter a number between 1 and $max_choice."
        return 1
    fi
}

# Function to get a valid list of choices from the user
get_list_of_choices() {
    local prompt_text="$1"
    local default_choices="$2"
    local max_choice=$3
    local choices_var_name=$4
    local user_input

    if [[ -n "$default_choices" ]]; then
        read -rp "$prompt_text (Default: $default_choices): " user_input
        if [[ -z "$user_input" ]]; then
            eval "$choices_var_name=($default_choices)"
            echo "Using default choices: $default_choices"
            return 0
        fi
    else
        read -rp "$prompt_text: " user_input
    fi

    local validated_choices=()
    for choice in $user_input; do
        if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le "$max_choice" ]]; then
            validated_choices+=("$choice")
        else
            echo "Invalid input: '$choice'. Please enter space-separated numbers between 1 and $max_choice."
            return 1
        fi
    done

    if [[ ${#validated_choices[@]} -eq 0 ]]; then
        echo "No valid choices entered. Please try again."
        return 1
    else
        eval "$choices_var_name=(${validated_choices[@]})"
        return 0
    fi
}


# Main function for detecting interfaces and getting user choices
detect_interfaces() {
    echo "--- Detecting network interfaces ---"
    mapfile -t interfaces_array < <(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo')
    
    echo "Available network interfaces:"
    for i in "${!interfaces_array[@]}"; do
        printf "%d) %s\n" $((i+1)) "${interfaces_array[$i]}"
    done

    WAN_IFACE_CHOICE=
    read -rp "Select your WAN (Internet-facing) interface number (Default: 1): " WAN_IFACE_CHOICE
    WAN_IFACE_CHOICE=${WAN_IFACE_CHOICE:-1}
    WAN_IFACE="${interfaces_array[$((WAN_IFACE_CHOICE-1))]}"
    echo "Selected WAN Interface: $WAN_IFACE"
    
    LAN_INTERFACES_ARRAY=()
    LAN_CHOICE_MAP=()
    for i in "${!interfaces_array[@]}"; do
        if [[ $i -ne $((WAN_IFACE_CHOICE-1)) ]]; then
            LAN_INTERFACES_ARRAY+=("${interfaces_array[$i]}")
            LAN_CHOICE_MAP+=($((i+1)))
        fi
    done

    echo "Available LAN interfaces to bridge:"
    for i in "${!LAN_INTERFACES_ARRAY[@]}"; do
        printf "%d) %s\n" "${LAN_CHOICE_MAP[$i]}" "${LAN_INTERFACES_ARRAY[$i]}"
    done
    
    LAN_IFACE_NUMBERS=()
    default_lan_choices_str=$(IFS=' '; echo "${LAN_CHOICE_MAP[*]}")
    
    read -rp "Select the numbers of your LAN interfaces to bridge (space-separated, Default: all non-WAN interfaces): " user_lan_input
    if [[ -z "$user_lan_input" ]]; then
        LAN_IFACE_NUMBERS=(${default_lan_choices_str[@]})
    else
        local temp_lan_iface_numbers
        if ! get_list_of_choices "" "$user_lan_input" "${#interfaces_array[@]}" "temp_lan_iface_numbers"; then
            echo "Invalid LAN interface selection. Exiting."
            exit 1
        fi
        LAN_IFACE_NUMBERS=("${temp_lan_iface_numbers[@]}")
    fi
    
    LAN_IFACES=""
    for num in "${LAN_IFACE_NUMBERS[@]}"; do
        LAN_IFACES+="${interfaces_array[$((num-1))]} "
    done
    LAN_IFACES=$(echo "$LAN_IFACES" | xargs)
    echo "Selected LAN Interfaces: $LAN_IFACES"


    read -rp "Do you want to configure a Wi-Fi Access Point? (y/n, default: n): " setup_wifi
    setup_wifi=${setup_wifi:-n}
    setup_wifi=$(echo "$setup_wifi" | tr '[:upper:]' '[:lower:]')

    if [[ "$setup_wifi" == "y" ]]; then
        WIFI_IFACE_CHOICE=
        wifi_interfaces_available=0
        for iface in $LAN_IFACES; do
            if [[ "$iface" == "wlp"* || "$iface" == "wlan"* ]]; then
                 echo "Using wireless interface: $iface"
                 WIFI_IFACE="$iface"
                 wifi_interfaces_available=1
                 break
            fi
        done

        if [[ "$wifi_interfaces_available" -eq 0 ]]; then
            echo "No wireless interface was detected as part of the LAN interfaces. Skipping Wi-Fi setup."
            setup_wifi="n"
        else
            read -rp "Enter your Wi-Fi SSID (e.g., TheRouter): " WIFI_SSID
            read -s -p "Enter your Wi-Fi Password: " WIFI_PASS
            echo
            if [[ -z "$WIFI_SSID" || -z "$WIFI_PASS" ]]; then
                echo "Wi-Fi SSID and password cannot be empty. Skipping Wi-Fi setup."
                setup_wifi="n"
            fi
        fi
    fi
    
    echo "--- LAN IP Configuration ---"
    read -rp "Enter the static IP address and CIDR for the bridge (e.g., 192.168.1.1/24, default: 192.168.42.1/24): " LAN_IP_CIDR
    LAN_IP_CIDR=${LAN_IP_CIDR:-"192.168.42.1/24"}
    LAN_IP=$(echo "$LAN_IP_CIDR" | cut -d'/' -f1)
    
    read -rp "Enter the DHCP start IP (e.g., 192.168.42.100, default: 192.168.42.100): " DHCP_START
    DHCP_START=${DHCP_START:-"192.168.42.100"}
    
    read -rp "Enter the DHCP end IP (e.g., 192.168.42.200, default: 192.168.42.200): " DHCP_END
    DHCP_END=${DHCP_END:-"192.168.42.200"}

    read -rp "Enter your desired local domain name (e.g., home.lan, default: home.lan): " LOCAL_DOMAIN
    LOCAL_DOMAIN=${LOCAL_DOMAIN:-"home.lan"}
}

# Function to set up login credentials in users.json
setup_login_credentials() {
    echo "--- Setting up initial user credentials ---"
    read -rp "Enter a username for the web dashboard: " WEB_USERNAME
    read -rs -p "Enter a password for the web dashboard: " WEB_PASSWORD
    echo

    if [[ -z "$WEB_USERNAME" || -z "$WEB_PASSWORD" ]]; then
        echo "Username and password cannot be empty. Exiting."
        exit 1
    fi

    HASHED_PASSWORD=$(printf "%s" "$WEB_PASSWORD" | openssl dgst -sha256 | awk '{print $2}')
    
    cat <<EOF | sudo tee /var/www/html/users.json > /dev/null
{
  "users": [
    {
      "username": "$WEB_USERNAME",
      "password_hash": "$HASHED_PASSWORD"
    }
  ]
}
EOF
    
    echo "Initial user '$WEB_USERNAME' created successfully."
}

# --- 2. DEPENDENCY INSTALLATION ---
install_dependencies() {
    echo "--- Installing required packages ---"
    sudo apt update
    # Removed dnsutils (for dig) and ipset as they are no longer needed for blocking
    if [[ "$setup_wifi" == "y" ]]; then
        sudo apt install -y net-tools dnsmasq hostapd wireless-tools iw iptables-persistent apache2 php libapache2-mod-php jq ipcalc dos2unix openssl bridge-utils wget curl
    else
        sudo apt install -y net-tools dnsmasq iptables-persistent apache2 php libapache2-mod-php jq ipcalc dos2unix openssl bridge-utils wget curl
    fi

    # YQ is needed for Access Control features
    if ! command -v yq &>/dev/null; then
        echo "Installing yq (Go version)... (Needed for Access Control features)"
        YQ_VERSION="v4.42.1" # Check for the latest version on GitHub: https://github.com/mikefarah/yq/releases
        YQ_BINARY="yq_linux_amd64"
        wget "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY}" -O /usr/local/bin/yq || { echo "Failed to download yq. Check internet connection or YQ_VERSION/YQ_BINARY."; exit 1; }
        sudo chmod +x /usr/local/bin/yq
    fi
}

# --- 3. SYSTEM CONFIGURATION ---
configure_system() {
    echo "--- Configuring system settings ---"
    
    echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip-forward.conf > /dev/null
    sudo sysctl -p /etc/sysctl.d/99-ip-forward.conf
    
    echo "Setting up basic firewall rules..."
    
    # Flush all chains before adding new rules
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X

    # Set default policies (important order)
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT ACCEPT

    # --- INPUT Chain (Traffic to the Router Itself) ---
    # Allow established/related connections
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    # Allow loopback traffic
    sudo iptables -A INPUT -i lo -j ACCEPT
    # Allow router's own DNS/HTTP(S) access from LAN (br0)
    sudo iptables -A INPUT -i br0 -p udp --dport 53 -j ACCEPT
    sudo iptables -A INPUT -i br0 -p tcp --dport 53 -j ACCEPT
    sudo iptables -A INPUT -i br0 -p tcp --dport 80 -j ACCEPT
    sudo iptables -A INPUT -i br0 -p tcp --dport 443 -j ACCEPT
    # Allow DHCP (client and server) traffic on br0
    sudo iptables -A INPUT -i br0 -p udp --dport 67 -j ACCEPT
    sudo iptables -A INPUT -i br0 -p udp --dport 68 -j ACCEPT
    # Allow SSH access to the router from the internal network (br0)
    sudo iptables -A INPUT -i br0 -p tcp --dport 22 -j ACCEPT
    # Allow SSH access to the router from WAN (OPTIONAL - DANGER if not protected)
    # sudo iptables -A INPUT -i "$WAN_IFACE" -p tcp --dport 22 -j ACCEPT # Uncomment with caution!

    # --- FORWARD Chain (Traffic Passing Through the Router) ---
    # Allow established/related forwarded connections
    sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # IPset for 'no_internet_access' for clients
    echo "Creating ipset 'no_internet_access'..."
    sudo ipset create no_internet_access hash:ip || { echo "Warning: Failed to create ipset 'no_internet_access'." >&2; }
    # Blocking rule for 'no_internet_access' (Still needed here, insert after RELATED,ESTABLISHED)
    sudo iptables -A FORWARD -m set --match-set no_internet_access src -j DROP


    # GENERAL FORWARDING ALLOW (FOR ALL ALLOWED TRAFFIC)
    # This comes after specific DROP rules.
    # Allow all general outbound traffic from the LAN (br0) to the WAN ($WAN_IFACE)
    sudo iptables -A FORWARD -i br0 -o "$WAN_IFACE" -j ACCEPT

    # --- NAT Table (Traffic Masquerading/Redirection) ---
    # Force LAN DNS to router's dnsmasq (PREROUTING)
    echo "Adding DNS redirection rules (NAT PREROUTING)..."
    sudo iptables -t nat -A PREROUTING -i br0 -p udp --dport 53 -j DNAT --to-destination "$LAN_IP"
    sudo iptables -t nat -A PREROUTING -i br0 -p tcp --dport 53 -j DNAT --to-destination "$LAN_IP"

    # Apply iptables NAT (Masquerading) for internet access (POSTROUTING)
    sudo iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    
    sudo netfilter-persistent save

    sudo systemctl disable systemd-resolved
    sudo systemctl stop systemd-resolved
    sudo rm -f /etc/resolv.conf
    echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf > /dev/null
}

# --- 4. CONFIG FILE GENERATION (this function remains the same as before, generates basic configs) ---
generate_configs() {
    echo "--- Generating configuration files ---"
    
    NETPLAN_CONFIG="network:
  version: 2
  renderer: networkd
  ethernets:
    $WAN_IFACE:
      dhcp4: true
    "
    LAN_IFS_TO_BRIDGE=""
    for iface in $LAN_IFACES; do
      if [ "$iface" != "$WAN_IFACE" ]; then
        NETPLAN_CONFIG+="
    $iface:
      dhcp4: no"
        LAN_IFS_TO_BRIDGE+="$iface "
      fi
    done
    LAN_IFS_TO_BRIDGE=$(echo "$LAN_IFS_TO_BRIDGE" | xargs)

    NETPLAN_CONFIG+="
  bridges:
    br0:
      interfaces: [$(echo $LAN_IFS_TO_BRIDGE | sed 's/ /, /g')]
      dhcp4: no
      addresses: [$LAN_IP_CIDR]
      nameservers:
        addresses: [$LAN_IP, 8.8.8.8, 8.8.4.4]
"
    echo "$NETPLAN_CONFIG" | sudo tee /etc/netplan/01-network-config.yaml > /dev/null
    sudo chmod 640 /etc/netplan/01-network-config.yaml
    sudo chown root:www-data /etc/netplan/01-network-config.yaml
    sudo chmod 775 /etc/netplan/ # Set correct directory permissions for backup to work
    sudo netplan apply
    
    sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null
    NETMASK=$(ipcalc -n "$LAN_IP_CIDR" 2>/dev/null | awk '/Netmask:/ {print $2}')
    if [[ -z "$NETMASK" ]]; then
        echo "Warning: Could not determine netmask for $LAN_IP_CIDR. DHCP option 1 might be incorrect." >&2
        if [[ "$LAN_IP_CIDR" =~ /([0-9]+)$ ]]; then
            CIDR_BITS=${BASH_REMATCH[1]}
            if [[ "$CIDR_BITS" -eq 24 ]]; then
                NETMASK="255.255.255.0"
                echo "Using default 255.55.255.0 netmask for /24 CIDR." >&2
            fi
        fi
    fi

    cat <<EOF | sudo tee /etc/dnsmasq.conf > /dev/null
# /etc/dnsmasq.conf
interface=br0
listen-address=127.0.0.1,$LAN_IP
except-interface=$WAN_IFACE
no-dhcp-interface=$WAN_IFACE
domain=$LOCAL_DOMAIN
dhcp-range=$DHCP_START,$DHCP_END,12h
dhcp-option=3,$LAN_IP
dhcp-option=6,$LAN_IP
dhcp-option=1,$NETMASK
server=8.8.8.8
server=8.8.4.4
cache-size=1000
domain-needed
bogus-priv
rebind-domain-ok=/$LOCAL_DOMAIN/
log-facility=/var/log/dnsmasq.log
log-queries
EOF
    sudo touch /var/log/dnsmasq.log
    sudo chown root:adm /var/log/dnsmasq.log
    sudo chmod 640 /var/log/dnsmasq.log

    if [[ "$setup_wifi" == "y" ]]; then
        cat <<EOF | sudo tee /etc/hostapd/hostapd.conf > /dev/null
interface=$WIFI_IFACE
bridge=br0
driver=nl80211
ssid=$WIFI_SSID
hw_mode=g
channel=6
country_code=AU
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-40]
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$WIFI_PASS
nas_identifier=MyRouterAP
EOF
        sudo sed -i 's/^#DAEMON_CONF=""/DAEMON_CONF="\/etc\/hostapd\/hostapd.conf"/' /etc/default/hostapd
    fi

    echo "--- Creating update_hostapd.sh script ---"
    sudo mkdir -p ./scripts/
    cat <<'EOF' | sudo tee ./scripts/update_hostapd.sh > /dev/null
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

sudo sed -i.bak -E "s/^(ssid=.*/ssid=$NEW_SSID/" "$HOSTAPD_CONF" && \
sudo sed -i.bak -E "s/^(wpa_passphrase=.*/wpa_passphrase=$NEW_PASS/" "$HOSTAPD_CONF"

sudo systemctl restart hostapd

if [ $? -eq 0 ]; then
    echo "hostapd configuration updated and service restarted successfully."
    exit 0
else
    echo "Error: Failed to restart hostapd service." >&2
    exit 1
fi
EOF
    sudo chmod +x ./scripts/update_hostapd.sh

    echo "--- Correcting script line endings ---"
    if [ -f "./scripts/update_blocked_ips.sh" ]; then # This script is now mostly obsolete, but still copy if present.
        dos2unix ./scripts/update_blocked_ips.sh
    fi
    if [ -f "./scripts/update_net_stats.sh" ]; then
        dos2unix ./scripts/update_net_stats.sh
    fi
    if [ -f "./scripts/update_hostapd.sh" ]; then
        dos2unix ./scripts/update_hostapd.sh
    fi
    
    sudo mkdir -p /usr/local/bin/

    sudo cp ./scripts/update_blocked_ips.sh /usr/local/bin/ # Copy it, even if not directly used for blocking
    sudo cp ./scripts/update_net_stats.sh /usr/local/bin/
    sudo cp ./scripts/update_hostapd.sh /usr/local/bin/

    sudo chmod +x /usr/local/bin/update_blocked_ips.sh
    sudo chmod +x /usr/local/bin/update_net_stats.sh
    sudo chmod +x /usr/local/bin/update_hostapd.sh

    echo "--- Creating PHP config file ---"
    cat <<EOF | sudo tee /var/www/html/config.php > /dev/null
<?php
// This file is automatically generated by the install.sh script.
// Do not edit this file directly.
\$wan_interface = '$WAN_IFACE';
?>
EOF

    echo "--- Creating check_device_status.php script ---"
    cat <<'EOF' | sudo tee /var/www/html/check_device_status.php > /dev/null
<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
    exit();
}

function secure_shell_exec_no_log($command) {
    $output = shell_exec($command . ' 2>&1');
    return trim($output);
}

if (isset($_GET['ip'])) {
    $ip = escapeshellarg($_GET['ip']);
    $ping_command = "/bin/ping -c 1 -W 1 $ip";
    $ping_output = secure_shell_exec_no_log($ping_command);

    if (strpos($ping_output, ' 0% packet loss') !== false) {
        echo json_encode(['status' => 'online']);
    } else {
        if (strpos($ping_output, 'Operation not permitted') !== false || strpos($ping_output, 'unknown host') !== false || strpos(trim($ping_output), 'ping: sendmsg: Operation not permitted') !== false) {
             error_log("Ping command failed for IP $ip: $ping_output");
             echo json_encode(['status' => 'error', 'message' => 'Ping command error: ' . $ping_output]);
        } else {
            echo json_encode(['status' => 'offline']);
        }
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'No IP provided']);
}
?>
EOF
    sudo chown www-data:www-data /var/www/html/check_device_status.php
    sudo chmod 644 /var/www/html/check_device_status.php
}

setup_web_interface() {
    echo "--- Setting up the web interface ---"
    
    sudo rm -f /var/www/html/index.html
    
    if [ -d "./web/" ]; then
        sudo cp -r ./web/* /var/www/html/
    else
        echo "Warning: ./web/ directory not found. Web interface files not copied." >&2
    fi
    
    sudo touch /var/www/html/users.json
    sudo chown www-data:www-data /var/www/html/users.json
    sudo chmod 660 /var/www/html/users.json
    
    sudo rm -f /var/www/html/credentials.php
    
    sudo touch /var/www/html/blocked_domains.txt
    
    sudo chown -R www-data:www-data "$REMOTE_WEB_ROOT"
    sudo find "$REMOTE_WEB_ROOT" -type f -exec sudo chmod 644 {} +
    sudo find "$REMOTE_WEB_ROOT" -type d -exec sudo chmod 755 {} +

    echo "Adding sudo rule for www-data to run scripts, network commands, and read logs..."
    sudo mkdir -p /etc/sudoers.d/
    echo "www-data ALL=(root) NOPASSWD: /usr/local/bin/update_blocked_ips.sh, /usr/sbin/ipset add no_internet_access *, /usr/sbin/ipset del no_internet_access *, /usr/sbin/ipset flush no_internet_access, /usr/local/bin/update_hostapd.sh, /usr/bin/systemctl restart hostapd, /bin/ping, /usr/sbin/netplan apply, /usr/local/bin/yq, /usr/sbin/ip link set * up, /usr/sbin/ip link set * down, /usr/bin/tee /etc/netplan/01-network-config.yaml, /usr/bin/tail -n *, /usr/bin/tail -n 5000 /var/log/syslog, /usr/bin/tail -n 5000 /var/log/kern.log, /usr/bin/tail -n 5000 /var/log/auth.log, /usr/bin/tail -n 5000 /var/log/apache2/access.log, /usr/bin/tail -n 5000 /var/log/apache2/error.log, /usr/bin/tail -n 5000 /var/log/dnsmasq.log, /usr/sbin/iptables -A FORWARD -d * -j DROP, /usr/sbin/iptables -D FORWARD -d * -j DROP, /usr/sbin/iptables -L FORWARD -n -v --line-numbers, /usr/sbin/ipset create *, /usr/sbin/ipset destroy *, /usr/sbin/ipset add *, /usr/sbin/ipset list *" | sudo tee /etc/sudoers.d/www-data_firewall > /dev/null
    sudo chmod 0440 /etc/sudoers.d/www-data_firewall
    
    echo "Setting permissions for dnsmasq.leases file..."
    sudo mkdir -p /var/lib/misc/
    sudo touch /var/lib/misc/dnsmasq.leases
    sudo chown www-data:www-data /var/lib/misc/dnsmasq.leases
    sudo chmod 660 /var/lib/misc/dnsmasq.leases
}

# --- 5. PERMISSIONS & SERVICES ---
configure_services() {
    echo "--- Configuring services and permissions ---"
    
    if [[ "$setup_wifi" == "y" ]]; then
        sudo systemctl unmask hostapd
        sudo systemctl enable hostapd
        sudo systemctl start hostapd
    fi

    sudo systemctl restart dnsmasq
    sudo systemctl enable dnsmasq
    sudo systemctl restart apache2
    if ! dpkg -s php-sessions &>/dev/null; then
        echo "php-sessions not found, attempting to install..."
        sudo apt install php-sessions -y
    fi
    
    sudo chmod 660 /var/lib/misc/dnsmasq.leases
    sudo chown www-data:www-data /var/lib/misc/dnsmasq.leases
    sudo usermod -aG dnsmasq www-data
    sudo chmod g+r /var/lib/misc/dnsmasq.leases
    
    if command -v setcap &>/dev/null; then
        PING_PATH=$(which ping)
        if [ -n "$PING_PATH" ]; then
            echo "Attempting to set CAP_NET_RAW capability for $PING_PATH..."
            sudo setcap cap_net_raw+ep "$PING_PATH" || echo "Warning: Failed to set CAP_NET_RAW capability for $PING_PATH. Ping might still require sudo if not already configured." >&2
        else
            echo "Warning: 'ping' command not found, cannot set CAP_NET_RAW capability." >&2
        fi
    else
        echo "Warning: 'setcap' command not found. Please install 'libcap2-bin' for proper ping permissions." >&2
    fi
    # Add www-data to adm group for log reading if needed
    if ! getent group adm | grep -q "www-data"; then
        echo "Adding www-data to 'adm' group for log access..."
        sudo usermod -aG adm www-data
    fi
}

# --- 6. FIRST-RUN SCRIPT EXECUTION ---
run_first_time_scripts() {
    echo "--- Running custom scripts for the first time to ensure they work ---"

    echo "Executing update_blocked_ips.sh..." # This script will now only manage no_internet_access
    if [ -f "/usr/local/bin/update_blocked_ips.sh" ]; then
        sudo /usr/local/bin/update_blocked_ips.sh
        if [ $? -ne 0 ]; then
            echo "Warning: update_blocked_ips.sh exited with an error, but the installation will continue."
        else
            echo "update_blocked_ips.sh completed successfully."
        fi
    else
        echo "Warning: update_blocked_ips.sh not found at /usr/local/bin/. Skipping execution."
    fi

    echo "Executing update_net_stats.sh..."
    if [ -f "/usr/local/bin/update_net_stats.sh" ]; then
        sudo /usr/local/bin/update_net_stats.sh
        if [ $? -ne 0 ]; then
            echo "Warning: update_net_stats.sh exited with an error, but the installation will continue."
        else
            echo "update_net_stats.sh completed successfully."
        fi
    else
        echo "Warning: update_net_stats.sh not found at /usr/local/bin/. Skipping execution."
    fi
}

# --- 7. MAIN EXECUTION FLOW ---
main() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root or with sudo."
        exit 1
    fi
    
    REQUIRED_COMMANDS=(ip awk tee sed openssl iptables systemctl dos2unix ipcalc jq wget curl)
    MISSING_COMMANDS=()
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            MISSING_COMMANDS+=("$cmd")
        fi
    done

    if [ ${#MISSING_COMMANDS[@]} -ne 0 ]; then
        echo "Notice: Some commands are missing but will be installed during the dependency installation step: ${MISSING_COMMANDS[*]}"
    fi

    detect_interfaces
    install_dependencies
    configure_system
    generate_configs
    setup_web_interface
    setup_login_credentials
    configure_services
    run_first_time_scripts

    echo "--- Installation Complete! ---"
    echo "Your router/firewall should now be configured."
    echo "Access the web interface at http://$LAN_IP"
}

main "$@"
