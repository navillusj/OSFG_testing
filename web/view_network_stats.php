<?php
$stats_file_path = '/var/log/network_stats.json';

$network_stats = null;
$error_message = '';

if (file_exists($stats_file_path) && is_readable($stats_file_path)) {
    $json_content = file_get_contents($stats_file_path);
    if ($json_content === false) {
        $error_message = 'Error: Could not read network stats file. Check permissions for ' . htmlspecialchars($stats_file_path);
    } else {
        $network_stats = json_decode($json_content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $error_message = 'Error: Could not parse JSON data. ' . json_last_error_msg();
            $network_stats = null;
        }
    }
} else {
    $error_message = 'Network stats file not found or not readable at ' . htmlspecialchars($stats_file_path) . '. Ensure the cron job has run.';
}

function formatBytes($bytes, $precision = 2) {
    $bytes = (float)$bytes;
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    if ($bytes == 0) return '0 B';
    $pow = floor(log($bytes) / log(1024));
    $pow = min($pow, count($units) - 1);
    $value = $bytes / (1 << (10 * $pow));
    return round($value, $precision) . ' ' . $units[$pow];
}

$last_updated = 'N/A';
if ($network_stats && isset($network_stats['timestamp'])) {
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
</head>
<body>
    <div class="container">
        <h1>Network Usage Dashboard</h1>
        <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>

        <?php if ($error_message): ?>
            <div class="error"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>

        <div class="note">
            <p><strong>Last Updated:</strong> <?php echo htmlspecialchars($last_updated); ?></p>
            <p>Data is refreshed automatically by a server-side cron job.</p>
        </div>

        <?php if ($network_stats): ?>
            <div class="grid">
                <div class="stat-card">
                    <h3>Upload</h3>
                    <p><?php echo formatBytes($network_stats['delta_rx_bytes']); ?></p>
                    <small>Interface: <?php echo htmlspecialchars($network_stats['interface']); ?></small>
                </div>
                <div class="stat-card">
                    <h3>Download</h3>
                    <p><?php echo formatBytes($network_stats['delta_tx_bytes']); ?></p>
                    <small>Interface: <?php echo htmlspecialchars($network_stats['interface']); ?></small>
                </div>
            </div>

            <div class="card" style="margin-top: 30px;">
                <h3>Top User Information</h3>
                <div class="hint" style="margin-top: 0;">
                    <strong>Note:</strong> Accurately identifying top users requires specialized tools like NetFlow or nethogs. This section is a placeholder.
                </div>
                <pre><?php echo htmlspecialchars($network_stats['top_ips_info']); ?></pre>
            </div>

        <?php else: ?>
            <div class="warning">
                <p>No network statistics data available yet. Please ensure the `update_net_stats.sh` script is running successfully via cron.</p>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
