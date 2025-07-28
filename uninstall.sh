#!/bin/bash
#
# This script uninstalls the custom router/firewall configuration and software.
# It reverts changes made by the install.sh script.
#
# WARNING: This script is destructive. It will remove network configurations,
# firewall rules, and all project files. Use with caution.
#
# Usage: sudo ./uninstall.sh

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root or with sudo."
   exit 1
fi

echo "--- Stopping services ---"
systemctl stop dnsmasq hostapd apache2 2>/dev/null
systemctl disable dnsmasq hostapd apache2 2>/dev/null

echo "--- Reverting Network Configuration ---"
# Remove Netplan configuration file
rm -f /etc/netplan/01-network-config.yaml
# Remove custom dnsmasq.conf and restore backup
rm -f /etc/dnsmasq.conf
mv /etc/dnsmasq.conf.bak /etc/dnsmasq.conf 2>/dev/null
# Remove hostapd configuration files
rm -f /etc/hostapd/hostapd.conf
sed -i 's/^DAEMON_CONF=.*$/#DAEMON_CONF=""/' /etc/default/hostapd

echo "--- Removing IPTables and IPSet Rules ---"
# Flush all iptables rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
# Set default policies back to ACCEPT for safety
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
# Save the new, clean rules
netfilter-persistent save
# Destroy IPsets
ipset destroy blocked_sites 2>/dev/null
ipset destroy no_internet_access 2>/dev/null

echo "--- Reverting System Settings ---"
# Disable IP forwarding
rm -f /etc/sysctl.d/99-ip-forward.conf
sysctl -p /dev/null
# Re-enable systemd-resolved and restore resolv.conf
systemctl enable systemd-resolved 2>/dev/null
systemctl start systemd-resolved 2>/dev/null
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo "--- Removing Project Files ---"
# Remove custom scripts from /usr/local/bin/
rm -f /usr/local/bin/update_blocked_ips.sh
rm -f /usr/local/bin/update_net_stats.sh
rm -f /usr/local/bin/update_hostapd.sh
# Remove web interface files
rm -rf /var/www/html/*
# Remove cron job file
rm -f /etc/cron.d/my_router_stats
# Remove sudoers file
rm -f /etc/sudoers.d/www-data_firewall

echo "--- Uninstalling Packages ---"
# Purge all installed packages to remove them and their config files
apt purge -y dnsmasq hostapd ipset iptables-persistent apache2 php libapache2-mod-php jq dnsutils ipcalc dos2unix openssl net-tools

echo "--- Cleanup Complete ---"
echo "The system has been reverted. You may need to reboot for all changes to take full effect."
