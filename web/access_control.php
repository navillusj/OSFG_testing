<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Set headers to prevent caching
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");

// Function to check if an IP is in the ipset
function isIpBlocked($ip) {
    exec("sudo ipset test no_internet_access {$ip} 2>&1", $output, $return_var);
    return $return_var === 0;
}

// Function to get a list of connected devices from dnsmasq's lease file
function getConnectedDevices() {
    $devices = [];
    $lease_file = "/var/lib/misc/dnsmasq.leases";

    if (file_exists($lease_file)) {
        $lines = file($lease_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $parts = explode(" ", $line);
            if (count($parts) >= 4) {
                $mac = strtolower($parts[1]);
                $ip = $parts[2];
                $hostname = $parts[3];

                if (!isset($devices[$ip])) {
                    $devices[$ip] = [
                        'ip' => $ip,
                        'mac' => $mac,
                        'hostname' => $hostname
                    ];
                }
            }
        }
    }
    return $devices;
}

$connectedDevices = getConnectedDevices();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Access Control</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body>

<div class="container">
    <h1>Internet Access Control for LAN</h1>
        <a href="index.php" class="button"><i class="fas fa-filter"></i>Back to main page</a>
    <div class="note">
        <p>Click the switch to toggle internet access for a device. Local network access is always allowed.
        <br>I found this to be a bit dicky, sometimes it's a double click or a single click...I know I'll get around to it</p>
    </div>

    <a href="flush_blocked.php" class="button sync-button" onclick="return confirm('Are you sure you want to flush ALL blocked devices?');">Flush All Blocked Devices</a>
    
    <div class="grid">
        <?php if (empty($connectedDevices)): ?>
            <div class="card">
                <p>No devices found in DHCP lease file.</p>
            </div>
        <?php else: ?>
            <?php foreach ($connectedDevices as $device): ?>
            <div class="card">
                <h3><i class="fas fa-network-wired"></i> <?php echo htmlspecialchars($device['hostname']); ?></h4>
                <p><strong>IP Address:</strong> <?php echo htmlspecialchars($device['ip']); ?></p>
                <p><strong>MAC Address:</strong> <?php echo htmlspecialchars(strtoupper($device['mac'])); ?></p>
                <div class="toggle-container">
                    <span>Internet Access:</span>
                    <form action="toggle_access.php" method="get" style="display:inline-block; margin-left: 10px;">
                        <input type="hidden" name="ip" value="<?php echo htmlspecialchars($device['ip']); ?>">
                        <label class="switch">
                            <input type="checkbox" name="action" value="add" onchange="this.form.submit()" <?php echo isIpBlocked($device['ip']) ? '' : 'checked'; ?>>
                            <span class="slider round"></span>
                        </label>
                    </form>
                </div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>

</body>
</html>
