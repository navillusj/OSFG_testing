<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Function to safely execute shell commands
function secure_shell_exec($command, $log_context = 'general') {
    error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $command));
    $output = shell_exec($command . ' 2>&1');
    if ($output === null) {
        error_log(sprintf("[%s] ERROR: Command failed for %s. Command: '%s'", date('Y-m-d H:i:s'), $log_context, $command));
        return "Error: Command failed or not found.";
    }
    return trim($output);
}

// Global variables
$message = '';
$error = '';
$hostapd_conf_path = '/etc/hostapd/hostapd.conf';

// --- Handle Wi-Fi settings form submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_wifi'])) {
    if (isset($_POST['ssid']) && isset($_POST['password'])) {
        $ssid = trim($_POST['ssid']);
        $password = trim($_POST['password']);

        if (empty($ssid) || empty($password)) {
            $error = "SSID and Password cannot be empty.";
        } else {
            $command = "sudo /usr/local/bin/update_hostapd.sh " . escapeshellarg($ssid) . " " . escapeshellarg($password) . " 2>&1";
            $output = shell_exec($command);
            
            if (strpos($output, 'Error:') === false) {
                $message = "Wi-Fi settings updated successfully. Service restarted.";
            } else {
                $error = "Failed to update Wi-Fi settings. " . htmlspecialchars($output);
            }
        }
    }
}

// Read current Wi-Fi settings to pre-populate the form
$current_ssid = 'N/A';
$current_pass = 'N/A';
if (file_exists($hostapd_conf_path)) {
    $conf_content = file_get_contents($hostapd_conf_path);
    if ($conf_content !== false) {
        if (preg_match('/^ssid=(.*)$/m', $conf_content, $matches)) {
            $current_ssid = $matches[1];
        }
        if (preg_match('/^wpa_passphrase=(.*)$/m', $conf_content, $matches)) {
            $current_pass = $matches[1];
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Settings</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body>
    <div class="container">
        <h1>Router Settings</h1>
        <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
        <a href="manage_users.php" class="button"><i class="fas fa-users"></i> Manage Users</a>
        
        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <h2>Wi-Fi Access Point Settings</h2>
        <div class="card">
            <p>Current SSID: <strong><?php echo htmlspecialchars($current_ssid); ?></strong></p>
            <p>Current Password: <strong><?php echo htmlspecialchars($current_pass); ?></strong></p>
            <form action="settings.php" method="post" style="margin-top: 20px;">
                <input type="hidden" name="update_wifi" value="1">
                <label for="ssid">New SSID:</label>
                <input type="text" id="ssid" name="ssid" value="<?php echo htmlspecialchars($current_ssid); ?>" required>
                <label for="password">New Password:</label>
                <input type="password" id="password" name="password" placeholder="Enter new password" required>
                <div class="form-actions">
                    <button type="submit" class="button"><i class="fas fa-save"></i> Update Wi-Fi Settings</button>
                </div>
            </form>
        </div>
        
        <div class="note">
            <p>Network Interface Management has been temporarily removed due to issues. It will be re-introduced in a future update.</p>
        </div>

    </div>
</body>
</html>
