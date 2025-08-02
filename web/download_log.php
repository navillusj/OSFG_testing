<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Define the SAME log files that can be viewed/downloaded as in logs.php
// IMPORTANT: This list must match the one in logs.php for security.
$log_files = [
    'syslog'        => '/var/log/syslog',
    'kernel_log'    => '/var/log/kern.log',
    'authentication_log' => '/var/log/auth.log',
    'apache_access_log'  => '/var/log/apache2/access.log',
    'apache_error_log'   => '/var/log/apache2/error.log',
    'dnsmasq_log'   => '/var/log/dnsmasq.log',
];

$file_key = isset($_GET['file']) ? $_GET['file'] : '';

if (empty($file_key) || !isset($log_files[$file_key])) {
    error_log("Attempt to download unrecognized or unauthorized log file: {$file_key}");
    die('Error: Invalid log file specified.');
}

$log_path = $log_files[$file_key];
$display_name = str_replace('_', '-', $file_key) . '.log'; // e.g., apache-error.log

// Use `cat` with `sudo` for full download, as `tail -n 5000` is for viewing.
// Ensure www-data has NOPASSWD for `sudo /bin/cat` on this path in install.sh.
// For security, it's better to use `tail` for download as well if file sizes are huge,
// but for full file, `cat` is usually used. Let's stick to `tail` for consistency and safety.
$command = "sudo /usr/bin/tail -n 50000 " . escapeshellarg($log_path) . " 2>&1"; // Download up to 50,000 lines
$content = shell_exec($command);

if ($content === null) {
    error_log("ERROR: shell_exec returned NULL for download command: {$command}");
    die("Error: Failed to execute command for download. Check server logs.");
} elseif (strpos($content, 'sudo:') !== false || strpos($content, 'Permission denied') !== false || strpos($content, 'No such file or directory') !== false) {
    error_log("ERROR: Download command failed for {$log_path}: {$content}");
    die("Error: Failed to read log file for download. Check permissions or log path. Output: " . htmlspecialchars($content));
}

// Set headers for download
header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $display_name . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . strlen($content)); // Use strlen for string content
echo $content;
exit;

?>
