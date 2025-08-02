<?php
// check_device_status.php
header('Content-Type: application/json');

session_start(); // Add this line
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401); // Unauthorized
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
    exit();
}

function secure_shell_exec_no_log($command) {
    $output = shell_exec($command . ' 2>&1');
    return trim($output);
}

if (isset($_GET['ip'])) {
    $ip = escapeshellarg($_GET['ip']); // Sanitize input
    // Use full path to ping
    $ping_command = "/bin/ping -c 1 -W 1 $ip"; // Use /bin/ping or /usr/bin/ping depending on your system
    $ping_output = secure_shell_exec_no_log($ping_command);

    if (strpos($ping_output, ' 0% packet loss') !== false) {
        echo json_encode(['status' => 'online']);
    } else {
        // Also check if ping command itself failed (e.g. permission denied)
        if (strpos($ping_output, 'Operation not permitted') !== false || strpos($ping_output, 'unknown host') !== false) {
             error_log("Ping command failed for IP $ip: $ping_output"); // Log the specific error
             echo json_encode(['status' => 'error', 'message' => 'Ping command error: ' . $ping_output]);
        } else {
            echo json_encode(['status' => 'offline']);
        }
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'No IP provided']);
}
?>
