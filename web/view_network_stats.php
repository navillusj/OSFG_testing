<?php
// Ensure session is started for authentication
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

$stats_file_path = '/var/log/network_stats.json'; // Ensure this path matches update_net_stats.sh

$network_stats = null;
$error_message = '';
$loading_message = 'Loading network statistics... Please ensure the cron job is configured and has run.';

// Attempt to read and parse the stats file
if (file_exists($stats_file_path) && is_readable($stats_file_path)) {
    $json_content = file_get_contents($stats_file_path);
    if ($json_content === false) {
        $error_message = 'Error: Could not read network stats file. Check permissions for ' . htmlspecialchars($stats_file_path);
    } else {
        $network_stats = json_decode($json_content, true);
        // FIX: Replaced JSON_LAST_ERROR_NONE with its numerical equivalent (0) for compatibility
        if (json_last_error() !== 0) { // JSON_ERROR_NONE has a value of 0
            $error_message = 'Error: Could not parse JSON data. ' . json_last_error_msg();
            $network_stats = null;
        }
    }
} else {
    $error_message = $loading_message; // Show loading message if file doesn't exist yet
}

// Function to format bytes for display
function formatBytes($bytes, $precision = 2) {
    $bytes = (float)$bytes;
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    if ($bytes == 0) return '0 B';
    $pow = floor(log($bytes) / log(1024));
    $pow = min($pow, count($units) - 1); // Cap at max unit
    $value = $bytes / (1 << (10 * $pow));
    return round($value, $precision) . ' ' . $units[$pow];
}

$last_updated = 'N/A';
if ($network_stats && isset($network_stats['timestamp'])) {
    // Set timezone for accurate display, e.g., 'Australia/Perth'
    date_default_timezone_set('Australia/Perth');
    $last_updated = date('Y-m-d H:i:s T', $network_stats['timestamp']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Usage Dashboard</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" integrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWr3W6A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        /* Specific styles for view_network_stats.php makeover */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin-top: 25px;
        }

        .stat-card-large {
            background-color: #2a2a2a;
            border: 1px solid #333;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 150px;
            border-left: 6px solid #4a90e2;
        }

        .stat-card-large h3 {
            margin-top: 0;
            font-size: 1.5em;
            color: #ffffff;
            border-bottom: none;
            padding-bottom: 0;
        }

        .stat-card-large .value {
            font-size: 2.8em;
            font-weight: 700;
            color: #50c878;
            margin: 10px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .stat-card-large .value.download {
            color: #4a90e2;
        }
        .stat-card-large .value.upload {
            color: #d9363e;
        }

        .stat-card-large .value i {
            font-size: 0.8em;
        }

        .stat-card-large small {
            color: #aaa;
            font-size: 0.85em;
            margin-top: 5px;
        }

        .info-card {
            background-color: #2a2a2a;
            border: 1px solid #333;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            margin-top: 30px;
        }

        .info-card h3 {
            border-bottom: 1px solid #444;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }

        .cron-info {
            font-size: 0.9em;
            color: #bbb;
            margin-top: 15px;
        }
        .cron-info code {
            background-color: #333;
            padding: 2px 5px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Usage Dashboard</h1>
        <div style="margin-bottom: 20px;">
            <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
            <a href="settings.php" class="button"><i class="fas fa-cog"></i> Settings</a>
            <a href="logs.php" class="button"><i class="fas fa-file-alt"></i> View Logs</a>
        </div>

        <?php if ($error_message && $error_message !== $loading_message): ?>
            <div class="error"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>

        <div class="note">
            <p><strong>Last Updated:</strong> <?php echo htmlspecialchars($last_updated); ?> <i class="fas fa-clock"></i></p>
            <p>Data is refreshed automatically by a server-side cron job, usually every 5 minutes.</p>
        </div>

        <?php if ($network_stats): ?>
            <div class="stat-grid">
                <div class="stat-card-large">
                    <h3>Download Traffic (since last update)</h3>
                    <p class="value download"><i class="fas fa-download"></i> <?php echo formatBytes($network_stats['delta_rx_bytes']); ?></p>
                    <small>Interface: <?php echo htmlspecialchars($network_stats['interface']); ?></small>
                </div>
                <div class="stat-card-large">
                    <h3>Upload Traffic (since last update)</h3>
                    <p class="value upload"><i class="fas fa-upload"></i> <?php echo formatBytes($network_stats['delta_tx_bytes']); ?></p>
                    <small>Interface: <?php echo htmlspecialchars($network_stats['interface']); ?></small>
                </div>
                <div class="stat-card-large">
                    <h3>Total Download (Current Cumulative)</h3>
                    <p class="value download"><i class="fas fa-arrow-alt-circle-down"></i> <?php echo formatBytes($network_stats['current_rx_bytes']); ?></p>
                    <small>Since last boot or interface reset.</small>
                </div>
                <div class="stat-card-large">
                    <h3>Total Upload (Current Cumulative)</h3>
                    <p class="value upload"><i class="fas fa-arrow-alt-circle-up"></i> <?php echo formatBytes($network_stats['current_tx_bytes']); ?></p>
                    <small>Since last boot or interface reset.</small>
                </div>
            </div>

            <div class="info-card">
                <h3>Top User Information</h3>
                <div class="hint" style="margin-top: 0;">
                    <p><i class="fas fa-info-circle"></i> <strong>Note:</strong> Accurately identifying top users by bandwidth requires advanced network monitoring tools (e.g., NetFlow/sFlow collectors, deep packet inspection, or complex <code>iptables</code> accounting rules with external parsing and database storage). This section currently provides a placeholder or information from basic accounting rules if enabled.</p>
                </div>
                <pre><?php echo htmlspecialchars($network_stats['top_ips_info']); ?></pre>
            </div>

        <?php else: ?>
            <div class="warning">
                <p><?php echo htmlspecialchars($error_message); ?></p>
                <div class="cron-info">
                    <p>To enable network statistics, ensure the <code>update_net_stats.sh</code> script is scheduled to run periodically via cron.</p>
                    <p><strong>Cron Job Setup:</strong></p>
                    <ol>
                        <li>SSH into your router.</li>
                        <li>Open your crontab for editing: <code>sudo crontab -e</code></li>
                        <li>Add the following line to the end of the file (e.g., to run every 5 minutes):<br>
                            <code>*/5 * * * * /usr/local/bin/update_net_stats.sh > /dev/null 2>&1</code></li>
                        <li>Save and exit the crontab editor.</li>
                        <li>Verify the path to <code>update_net_stats.sh</code> is correct (default is <code>/usr/local/bin/</code>).</li>
                    </ol>
                    <p>Also, ensure <code>/var/log/network_stats.json</code> exists and is readable by the web server user (<code>www-data</code>). You can create it with: <br>
                    <code>sudo touch /var/log/network_stats.json && sudo chown root:www-data /var/log/network_stats.json && sudo chmod 640 /var/log/network_stats.json</code></p>
                </div>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
