# My Open-Source Firewall
THIS REPO GETS UPDATED NIGHTLY AND MAY NOT WORK, I SUGGEST YOU DOWNLOAD THE STABLE VERSION https://github.com/navillusj/OSFG
<br>
<img width="523" height="963" alt="image" src="https://github.com/user-attachments/assets/3ddfef16-8bc5-4a94-b60c-e62b328f0140" />


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
<img width="1319" height="1224" alt="image" src="https://github.com/user-attachments/assets/deda446f-9027-418f-a0cb-dc232b967224" />


- **Network Statistics:** A web interface to display real-time network traffic statistics.
- **Login page** added a login page, during setup, installation script will prompt you to create login details.
- - you can also add your own logo. /var/www/html/logo.png
<img width="1285" height="901" alt="image" src="https://github.com/user-attachments/assets/cf2bb14b-317c-439e-8896-43d225f2aff2" />

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





