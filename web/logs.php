<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Define the log files that can be viewed/downloaded.
// IMPORTANT: Only list files that the www-data user has read access to,
// or for which you've explicitly granted sudo NOPASSWD access via `tail`.
$log_files = [
    'syslog'        => '/var/log/syslog',
    'kernel_log'    => '/var/log/kern.log',
    'authentication_log' => '/var/log/auth.log',
    'apache_access_log'  => '/var/log/apache2/access.log',
    'apache_error_log'   => '/var/log/apache2/error.log',
    'dnsmasq_log'   => '/var/log/dnsmasq.log', // Ensure dnsmasq is configured to log here
    // Add more log files as needed, ensuring 'www-data' has permissions
    // e.g., 'ufw_log' => '/var/log/ufw.log',
];

// Helper to execute commands with sudo for logs
function secure_sudo_tail($log_path) {
    // Only allow specific, predefined log paths
    global $log_files;
    if (!in_array($log_path, $log_files)) {
        error_log("Attempt to access unauthorized log file: {$log_path}");
        return "Error: Unauthorized log file path.";
    }

    // Use `tail` with `sudo` for files that require root access.
    // The `install.sh` script sets NOPASSWD for specific tail commands.
    // Ensure the `tail` command path is correct (`/usr/bin/tail`).
    $command = "sudo /usr/bin/tail -n 5000 " . escapeshellarg($log_path) . " 2>&1";
    $output = shell_exec($command);

    if ($output === null) {
        error_log("ERROR: shell_exec returned NULL for tail command: {$command}");
        return "Error: Command execution failed (NULL return). Check server logs.";
    } elseif (strpos($output, 'sudo:') !== false || strpos($output, 'Permission denied') !== false || strpos($output, 'No such file or directory') !== false) {
        error_log("ERROR: Tail command failed for {$log_path}: {$output}");
        return "Error: Failed to read log. Check permissions or log path. Output: " . htmlspecialchars($output);
    }
    return htmlspecialchars($output); // HTML-escape content for display
}

$selected_log_name = isset($_GET['view']) ? $_GET['view'] : '';
$log_content = '';
$current_log_path = '';

if (isset($log_files[$selected_log_name])) {
    $current_log_path = $log_files[$selected_log_name];
    $log_content = secure_sudo_tail($current_log_path);
} else if (!empty($selected_log_name)) {
    $log_content = "Error: Log file '{$selected_log_name}' not recognized or authorized.";
} else {
    $log_content = "Select a log file to view.";
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Log Viewer</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        .log-controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .log-view-area {
            background-color: #2a2a2a;
            color: #d0d0d0;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #333;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            white-space: pre-wrap; /* Preserve whitespace and wrap long lines */
            word-break: break-all; /* Break words to prevent overflow */
            max-height: 70vh; /* Limit height to prevent page becoming too long */
            overflow-y: auto; /* Enable scrolling for long logs */
            font-size: 0.85em;
        }
        .download-button {
            background-color: #50c878; /* Green */
        }
        .download-button:hover {
            background-color: #40a060;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Router Log Viewer</h1>
        <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
        <a href="settings.php" class="button"><i class="fas fa-cog"></i> Settings</a>

        <div class="log-controls">
            <?php foreach ($log_files as $key => $path): ?>
                <a href="logs.php?view=<?php echo htmlspecialchars($key); ?>" class="button <?php echo ($selected_log_name === $key) ? 'active' : ''; ?>">
                    <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $key))); ?> Log
                </a>
            <?php endforeach; ?>
            <?php if (!empty($selected_log_name) && isset($log_files[$selected_log_name])): ?>
                <a href="download_log.php?file=<?php echo htmlspecialchars($selected_log_name); ?>" class="button download-button">
                    <i class="fas fa-download"></i> Download Current Log
                </a>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2><?php echo !empty($selected_log_name) ? htmlspecialchars(ucwords(str_replace('_', ' ', $selected_log_name))) . ' Content' : 'Log Content'; ?></h2>
            <div class="log-view-area">
                <?php echo $log_content; ?>
            </div>
        </div>
    </div>
</body>
</html>
