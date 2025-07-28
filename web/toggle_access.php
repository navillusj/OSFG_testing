<?php
// Set headers to prevent caching
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");

// Check for the checkbox state
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];
    // If the checkbox is checked, it means "allow", so we delete from the blocked list.
    // If it's not checked, it means "block", so we add to the blocked list.
    $action = isset($_GET['action']) ? 'add' : 'del';

    // Validate the IP and action
    if (filter_var($ip, FILTER_VALIDATE_IP) && in_array($action, ['add', 'del'])) {
        $command = "sudo ipset {$action} no_internet_access {$ip} 2>&1";
        
        // Execute the command and capture the output
        shell_exec($command);
    }
}
// Redirect back to the main page
header("Location: /access_control.php");
exit();
?>