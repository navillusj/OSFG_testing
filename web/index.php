<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Include the dynamic WAN interface from the config file
include_once 'config.php';
// Fallback in case the config file is not found
if (!isset($wan_interface)) {
    $wan_interface = 'enp11s0f1'; // Default fallback
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubuntu Router Monitor</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" integrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWr3W6A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>Ubuntu Router Monitoring Dashboard</h1>
        <a href="manage_blocked_sites.php" class="button"><i class="fas fa-filter"></i> View/Edit Blocked Sites</a>
        <a href="view_network_stats.php" class="button"><i class="fas fa-chart-line"></i> View Network Stats</a>
        <a href="access_control.php" class="button"><i class="fas fa-user-shield"></i> Access Control</a>
        <a href="settings.php" class="button"><i class="fas fa-cog"></i> Settings</a>
        <a href="logout.php" class="button" style="background-color: #d9363e;"><i class="fas fa-sign-out-alt"></i> Logout</a>

        <div class="note">
            <div>
                <p><strong>Note:</strong> Hostname, DNS, and Gateway are system-wide settings, not specific to each individual interface.</p>
                <p><strong>Security Warning:</strong> This script executes shell commands. Ensure the web server user has minimal required permissions.</p>
                <p><strong>Interface Status:</strong> For bridged interfaces, their individual status might be misleading. The bridge status (e.g., br0) is the operative one.</p>
            </div>
        </div>

        <?php
        function secure_shell_exec($command, $log_context = 'general') {
            error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $command));
            $output = shell_exec($command . ' 2>&1');
            if ($output === null) {
                error_log(sprintf("[%s] ERROR: Command failed for %s. Command: '%s'", date('Y-m-d H:i:s'), $log_context, $command));
                return "Error: Command failed or not found.";
            }
            return trim($output);
        }
        ?>

        <h2>System Overview</h2>
        <div class="card">
            <p><strong>Hostname:</strong> <?php echo htmlspecialchars(secure_shell_exec('hostname', 'hostname')); ?></p>
            <p><strong>Uptime:</strong> <?php echo htmlspecialchars(secure_shell_exec('uptime -p', 'uptime')); ?></p>
            <p><strong>System Load:</strong> <?php echo htmlspecialchars(secure_shell_exec('cat /proc/loadavg | awk \'{print $1", "$2", "$3}\'', 'loadavg')); ?></p>
            <p><strong>Memory Usage:</strong> <?php echo htmlspecialchars(secure_shell_exec('free -h | awk \'/Mem:/ {print "Total: "$2", Used: "$3", Free: "$4}\'', 'memory')); ?></p>
            <p><strong>System DNS Servers:</strong></p>
            <pre><?php
                $resolv_conf_path = '/etc/resolv.conf';
                if (file_exists($resolv_conf_path)) {
                    $resolv_conf = file_get_contents($resolv_conf_path);
                    if ($resolv_conf !== false) {
                        preg_match_all('/^nameserver\s+([0-9.]+)/m', $resolv_conf, $matches);
                        echo !empty($matches[1]) ? htmlspecialchars(implode(", ", $matches[1])) : "No nameservers found.";
                    } else {
                        echo "Error reading " . htmlspecialchars($resolv_conf_path);
                    }
                } else {
                    echo htmlspecialchars($resolv_conf_path) . " not found.";
                }
            ?></pre>
            <p><strong>Default Gateway:</strong></p>
            <pre><?php
                $gateway = secure_shell_exec("ip route | grep default | awk '{print \$3}'", 'default_gateway');
                echo !empty($gateway) ? htmlspecialchars($gateway) : "Not found.";
            ?></pre>
        </div>

        <h2>Network Interfaces</h2>
        <div class="grid">
            <?php
            // Dynamically build the interfaces array
            $interfaces = [
                'lo'          => 'Loopback',
                $wan_interface => 'WAN Interface (Internet)',
                'br0'         => 'LAN Bridge (Internal Network)',
            ];
            
            // This is a more robust way to get all active interfaces
            $all_interfaces_output = secure_shell_exec("ip -o link show | awk -F': ' '{print \$2}' | grep -v 'lo'", 'all_interfaces');
            $all_interfaces_array = explode(' ', $all_interfaces_output);
            
            foreach ($all_interfaces_array as $iface) {
                if (!isset($interfaces[$iface])) {
                    $interfaces[$iface] = 'Other Interface';
                }
            }

            $ip_output = secure_shell_exec('ip -4 -json a', 'ip_addresses');
            $ip_data = json_decode($ip_output, true);

            if (json_last_error() !== JSON_ERROR_NONE || !is_array($ip_data)) {
                echo '<div class="error">Error decoding IP address information.</div>';
                $ip_data = [];
            }

            foreach ($interfaces as $iface_name => $description) {
                $ip_address = 'N/A';
                $status = 'Down';
                $status_class = 'status-down';

                foreach ($ip_data as $iface_info) {
                    if (isset($iface_info['ifname']) && $iface_info['ifname'] === $iface_name) {
                        if (isset($iface_info['operstate']) && $iface_info['operstate'] === 'UP') {
                           $status = 'Up';
                           $status_class = 'status-up';
                        }
                        if (isset($iface_info['addr_info']) && is_array($iface_info['addr_info'])) {
                            foreach ($iface_info['addr_info'] as $addr) {
                                if (isset($addr['family']) && $addr['family'] === 'inet' && isset($addr['local'])) {
                                    $ip_address = $addr['local'] . '/' . ($addr['prefixlen'] ?? 'N/A');
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            ?>
            <div class="card">
                <h3><i class="fas fa-ethernet"></i> <?php echo htmlspecialchars($iface_name); ?></h3>
                <p><?php echo htmlspecialchars($description); ?></p>
                <p><strong>Status:</strong> <span class="<?php echo $status_class; ?>"><?php echo htmlspecialchars($status); ?></span></p>
                <p><strong>IP Address:</strong> <?php echo htmlspecialchars($ip_address); ?></p>
            </div>
            <?php } ?>
        </div>

        <h2>Active Network Connections (TCP/UDP)</h2>
        <div class="card">
            <pre><?php
                $ss_command = 'ss -tanpu | head -n 20 2>&1';
                passthru($ss_command, $return_var);
                if ($return_var !== 0) {
                    echo "Error executing command: " . htmlspecialchars($ss_command);
                }
            ?></pre>
        </div>

        <h2>DNSMasq DHCP Leases</h2>
        <div class="grid">
        <?php
        $leasesFile = '/var/lib/misc/dnsmasq.leases';
        if (file_exists($leasesFile)) {
            $leases = file($leasesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($leases !== false && !empty($leases)) {
                foreach ($leases as $lease) {
                    $parts = explode(' ', trim($lease));
                    if (count($parts) >= 4) {
                        list($timestamp, $mac, $ip, $hostname) = $parts;
                        $date = is_numeric($timestamp) ? date('Y-m-d H:i:s', $timestamp) : 'N/A';
                        $hostnameDisplay = ($hostname !== '*') ? $hostname : 'Unknown Host';
            ?>
            <div class="card dhcp-card">
                <h3><i class="fas fa-network-wired"></i> <?php echo htmlspecialchars($hostnameDisplay); ?></h4>
                <p><strong>IP Address:</strong> <?php echo htmlspecialchars($ip); ?></p>
                <p><strong>MAC Address:</strong> <?php echo htmlspecialchars(strtoupper($mac)); ?></p>
                <p><strong>Lease Expires:</strong> <?php echo htmlspecialchars($date); ?></p>
            </div>
            <?php
                    }
                }
            } else {
                echo '<div class="note"><p>No active DHCP leases found.</p></div>';
            }
        } else {
            echo '<div class="note"><p>Leases file not found at ' . htmlspecialchars($leasesFile) . '. Ensure dnsmasq is running and configured correctly.</p></div>';
        }
        ?>
        </div>
    </div>
    <footer>
        <p>&copy; <?php echo date("Y"); ?> Ubuntu Router Monitor | Last Updated: <?php echo date("Y-m-d H:i:s AEST"); ?></p>
    </footer>
</body>
</html>
