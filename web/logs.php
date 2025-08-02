<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Define the log files that can be viewed.
$log_files = [
    'syslog'        => '/var/log/syslog',
    'kernel_log'    => '/var/log/kern.log',
    'authentication_log' => '/var/log/auth.log',
    'apache_access_log'  => '/var/log/apache2/access.log',
    'apache_error_log'   => '/var/log/apache2/error.log',
    'dnsmasq_log'   => '/var/log/dnsmasq.log',
];

// Helper to execute `tail` command with sudo for logs
function secure_sudo_tail($log_path, $lines_to_fetch = 5000) {
    global $log_files;
    if (!in_array($log_path, $log_files)) {
        error_log("Attempt to view unauthorized log file: {$log_path}");
        return "Error: Unauthorized log file path.";
    }

    $command = "sudo /usr/bin/tail -n " . (int)$lines_to_fetch . " " . escapeshellarg($log_path) . " 2>&1";
    $output = shell_exec($command);

    if ($output === null) {
        error_log("ERROR: shell_exec returned NULL for tail command: {$command}");
        return "Error: Command execution failed (NULL return). Check server logs.";
    } elseif (strpos($output, 'sudo:') !== false || strpos($output, 'Permission denied') !== false || strpos($output, 'No such file or directory') !== false) {
        error_log("ERROR: Tail command failed for {$log_path}: {$output}");
        return "Error: Failed to read log. Check permissions or log path. Output: " . htmlspecialchars($output);
    }
    return $output; // Return raw output for JS to handle, HTML escape in JS
}

$selected_log_name = isset($_GET['view']) ? $_GET['view'] : '';
$log_content_initial = '';
$current_log_path = '';

if (isset($log_files[$selected_log_name])) {
    $current_log_path = $log_files[$selected_log_name];
    $log_content_initial = secure_sudo_tail($current_log_path, 500); // Fetch smaller chunk initially for tailing
} else if (!empty($selected_log_name)) {
    $log_content_initial = "Error: Log file '{$selected_log_name}' not recognized or authorized.";
} else {
    $log_content_initial = "Select a log file to view.";
}

// Serve log content as plain text if it's an AJAX request for live tail
if (isset($_GET['action']) && $_GET['action'] === 'live_tail_fetch' && isset($log_files[$selected_log_name])) {
    header('Content-Type: text/plain'); // Serve as plain text for AJAX
    // For live tail, always fetch a fixed (and potentially large enough) number of recent lines
    echo secure_sudo_tail($log_files[$selected_log_name], 500); // Fetch last 500 lines for live tail
    exit();
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
            align-items: center;
        }
        .log-view-area {
            background-color: #2a2a2a;
            color: #d0d0d0;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #333;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 70vh;
            overflow-y: auto;
            font-size: 0.85em;
        }
        .live-tail-toggle-container {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .live-tail-label {
            color: #e0e0e0;
            font-weight: bold;
        }
        .switch {
            position: relative; display: inline-block; width: 40px; height: 24px;
        }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
            background-color: #d9363e; transition: .4s; border-radius: 24px;
        }
        .slider:before {
            position: absolute; content: ""; height: 16px; width: 16px; left: 4px; bottom: 4px;
            background-color: white; transition: .4s; border-radius: 50%;
        }
        input:checked + .slider { background-color: #50c878; }
        input:checked + .slider:before { transform: translateX(16px); }
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

            <?php if ($selected_log_name === 'dnsmasq_log'): ?>
            <div class="live-tail-toggle-container">
                <span class="live-tail-label">Live Tail:</span>
                <label class="switch">
                    <input type="checkbox" id="liveTailToggle">
                    <span class="slider round"></span>
                </label>
            </div>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2><?php echo !empty($selected_log_name) ? htmlspecialchars(ucwords(str_replace('_', ' ', $selected_log_name))) . ' Content' : 'Log Content'; ?></h2>
            <pre class="log-view-area" id="logContentArea"><?php echo htmlspecialchars($log_content_initial); ?></pre>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const logContentArea = document.getElementById('logContentArea');
            const liveTailToggle = document.getElementById('liveTailToggle');
            const selectedLogName = "<?php echo htmlspecialchars($selected_log_name); ?>"; // Pass selected log name to JS

            let liveTailInterval = null;

            async function fetchAndDisplayLog() {
                try {
                    const response = await fetch(`logs.php?action=live_tail_fetch&view=${selectedLogName}`);
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    const newLogContent = await response.text();
                    
                    logContentArea.textContent = newLogContent; // Replace content entirely
                    logContentArea.scrollTop = logContentArea.scrollHeight; // Scroll to bottom
                } catch (error) {
                    console.error("Error fetching live log:", error);
                    clearInterval(liveTailInterval);
                    liveTailInterval = null;
                    if(liveTailToggle) liveTailToggle.checked = false;
                    logContentArea.textContent += "\n--- Live tail stopped due to error ---";
                    logContentArea.scrollTop = logContentArea.scrollHeight;
                }
            }

            if (liveTailToggle) {
                liveTailToggle.addEventListener('change', () => {
                    if (liveTailToggle.checked) {
                        // Immediately fetch once, then start interval
                        fetchAndDisplayLog();
                        liveTailInterval = setInterval(fetchAndDisplayLog, 1500); // Fetch every 1.5 seconds
                    } else {
                        clearInterval(liveTailInterval);
                        liveTailInterval = null;
                    }
                });
            }
            
            // Initial scroll to bottom if log content is already loaded
            if (logContentArea.textContent.length > 0 && logContentArea.scrollHeight > logContentArea.clientHeight) {
                logContentArea.scrollTop = logContentArea.scrollHeight;
            }
        });
    </script>
</body>
</html>
