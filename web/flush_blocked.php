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

// Execute the command to flush the ipset
$command = "sudo ipset flush no_internet_access 2>&1";
shell_exec($command);

// Redirect back to the main access control page
header("Location: access_control.php");
exit();
?>
