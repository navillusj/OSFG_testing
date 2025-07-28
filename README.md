# My Open-Source Firewall
<img width="1047" height="2213" alt="image" src="https://github.com/user-attachments/assets/2d0ac7f5-3319-44e9-ab44-583db94b5160" />

An easy-to-configure, Ubuntu-based firewall/router with a web interface.
Be  nice to me, only doing this as a hobby :)
Happy to have people help
Yes there is AI generatated coding in here, but 99% of all troubleshooting is done by me.

## Current issues - PLEASE READ
- IPSET blocking IP
- IPSET blocking devices
- br0 is a bit iffy, local network will only work on specify lan port during setup

  
## Features
- **Network Bridge:** Combines wired and wireless interfaces into a single LAN.
- **DHCP & DNS:** Uses `dnsmasq` for local DHCP and DNS caching.
- **NAT:** Provides internet access to all connected devices.
- **Wi-Fi Access Point:** Configures a wireless access point with WPA2 security.
- **IP Blocking:** Blocks domains by adding their resolved IPs to an `ipset`.
- -- Still in progress
<img width="1057" height="703" alt="image" src="https://github.com/user-attachments/assets/4dabca20-98a9-4d42-879f-9c6536f12f26" />
<img width="1059" height="1056" alt="image" src="https://github.com/user-attachments/assets/62eee8ba-e372-4ff5-af3f-874e3b1a0f07" />

- **Network Statistics:** A web interface to display real-time network traffic statistics.
- **Login page** added a login page, during setup, installation script will prompt you to create login details.
- - you can also add your own logo. /var/www/html/logo.png
    <img width="580" height="1009" alt="image" src="https://github.com/user-attachments/assets/47bb5322-6102-4c8b-b36d-004e666db9f4" />
## Prerequisites
- A fresh installation of Ubuntu Server (LTS recommended).
- dos2unix
- -- I used 24.04.2
- A machine with at least two network interfaces (one for WAN, one or more for LAN/Wi-Fi).

```bash
git clone https://github.com/navillusj/my-opensource-firewall.git
cd my-opensource-firewall
sudo chmod +x ./install.sh
sudo apt update
sudo apt install dos2unix
sudo dos2unix install.sh
sudo ./install.sh
```
You will need to update the firewall rules as well, as they point towards "br0" and not "eth0"
You may need to manually run
```bash
sudo iptables -t nat -A POSTROUTING -o UPDATE-WAN-ID -j MASQUERADE
```
To view or make use of the "View IP Tables" page, you'll need to provide access to this. 
There is probs a better way. But at this stage, use the below commands.
Disbaled by default, again for obs reasons.

```bash
sudo visudo

www-data ALL=NOPASSWD: /usr/sbin/iptables
www-data ALL=NOPASSWD: /usr/sbin/iptables-save
www-data ALL=NOPASSWD: /usr/sbin/ip6tables
www-data ALL=NOPASSWD: /usr/sbin/ip6tables-save
```
## install_testing.sh
This script is for testing, it "SHOULD" work, but your results may vary.

## install_netplan_fix.sh
This script should fix the
```bash
** (process:11169): WARNING **: 08:44:26.915: Permissions for /etc/netplan/01-network-config.yaml are too open. Netplan configuration should NOT be accessible by others.
```
errors


