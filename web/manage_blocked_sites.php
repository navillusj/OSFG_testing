<?php
$domain_file_path = '/var/www/html/blocked_domains.txt';
$ipset_name = 'blocked_sites';
// The script is now located in a more standard system directory
$update_script_path = '/usr/local/bin/update_blocked_ips.sh';

$message = '';
$error = '';
$sync_output = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domains'])) {
    $new_domains_content = $_POST['domains'];
    if (is_writable($domain_file_path)) {
        if (file_put_contents($domain_file_path, $new_domains_content) !== false) {
            $message = 'Blocked domains list saved successfully.';
        } else {
            $error = 'Error: Could not write to the file. Check permissions.';
        }
    } else {
        $error = 'Error: File is not writable. Check permissions for ' . htmlspecialchars($domain_file_path);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sync_now'])) {
    if (file_exists($update_script_path) && is_executable($update_script_path)) {
        $command = "sudo " . escapeshellarg($update_script_path) . " 2>&1";
        $sync_output = shell_exec($command);
        if ($sync_output === null) {
            $error = "Error: Failed to execute the sync script. Check permissions, sudoers, and script path.";
        } else {
            $message .= " IPset sync initiated. Output: <pre>" . htmlspecialchars($sync_output) . "</pre>";
        }
    } else {
        $error = 'Error: Sync script not found or not executable at ' . htmlspecialchars($update_script_path);
    }
}

$current_domains_content = '';
if (file_exists($domain_file_path) && is_readable($domain_file_path)) {
    $current_domains_content = file_get_contents($domain_file_path);
    if ($current_domains_content === false) {
        $error = 'Error: Could not read the domain file. Check permissions.';
    }
} else {
    file_put_contents($domain_file_path, '');
    $error = 'Notice: Domain file not found. A new, empty file has been created at ' . htmlspecialchars($domain_file_path);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Blocked Sites</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" integrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWr3W6A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>Manage Blocked Websites</h1>
        <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>

        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <div class="warning">
            <strong>EXTREME SECURITY WARNING:</strong> The "Sync Now" button directly executes a `sudo` command from the web server. This is a major security risk if not configured precisely.
        </div>

        <form method="POST">
            <label for="domains">Enter one domain per line (comments start with #):</label><br>
            <textarea id="domains" name="domains" rows="20" placeholder="e.g.,&#x0A;example.com&#x0A;malicious-site.net&#x0A;# This is a comment"><?php echo htmlspecialchars($current_domains_content); ?></textarea>
            <div class="form-actions">
                <input type="submit" value="Save Changes" class="button">
                <input type="submit" name="sync_now" value="Sync Now" class="button sync-button" onclick="return confirm('WARNING: Are you sure you want to run the sync script with sudo?')">
            </div>
        </form>

        <div class="hint">
            <h3>Recommended Sync Method: Cron Job</h3>
            <p>For security and stability, it is strongly recommended to set up a `cron` job to run the update script periodically.
                <br>
            The script is located at: <code><?php echo htmlspecialchars($update_script_path); ?></code>
            Example `cron` entry (run <code>sudo crontab -e</code>):
            <pre>*/5 * * * * <?php echo htmlspecialchars($update_script_path); ?> &gt;/dev/null 2&gt;&amp;1</pre>
           </p>
        </div>
    </div>
</body>
</html>
