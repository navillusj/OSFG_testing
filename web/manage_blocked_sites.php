<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Global variables for messages
$message = '';
$error = '';

// Path to iptables binary
$iptables_path = '/usr/sbin/iptables';
$sudo_path = '/usr/bin/sudo'; // Explicit sudo path

// Function to securely execute iptables commands via sudo
function secure_iptables_exec($command_args, $log_context = 'iptables_mgmt') {
    global $sudo_path, $iptables_path;

    // Build the full command string for exec
    // Use sudo, then iptables path, then the arguments
    $full_command = "{$sudo_path} {$iptables_path} " . implode(" ", array_map('escapeshellarg', $command_args));
    
    error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $full_command));
    
    $output_lines = [];
    $return_var = 0;
    exec($full_command . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);

    error_log(sprintf("[%s] DEBUG: Raw output for iptables command '%s': '%s'", date('Y-m-d H:i:s'), $full_command, $output));
    error_log(sprintf("[%s] DEBUG: Return variable for iptables command '%s': %d", date('Y-m-d H:i:s'), $full_command, $return_var));

    if ($return_var !== 0) {
        error_log(sprintf("[%s] ERROR: iptables command failed for %s. Return var: %d. Output: '%s'", date('Y-m-d H:i:s'), $log_context, $return_var, $output));
        return "Error: Command exited with status {$return_var}: " . $output;
    }
    
    return ''; // Return empty string on success
}

// Function to validate an IP address (IPv4 or IPv6 with optional CIDR)
function isValidIpAddress($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false || preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}\/(1[6-9]|[2-3][0-2])$/', $ip) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

// Fetch currently blocked IPs
function getBlockedIps() {
    global $iptables_path, $sudo_path;
    $blocked_ips = [];
    
    // Get rules from FORWARD chain that drop traffic to a specific destination
    // Filter for rules that match: "-j DROP -d <IP_ADDRESS>"
    // This assumes your blocking rule is specifically "-A FORWARD -d <IP_ADDRESS> -j DROP"
    $command = "{$sudo_path} {$iptables_path} -L FORWARD -n -v --line-numbers 2>&1";
    $output = shell_exec($command);

    if ($output === null || strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("ERROR: Failed to list iptables FORWARD rules: {$output}");
        return ['error' => "Failed to retrieve current iptables rules: " . htmlspecialchars($output)];
    }

    $lines = explode("\n", $output);
    foreach ($lines as $line) {
        $line = trim($line);
        // Match lines that look like: "num target prot opt source destination ... d:IP_ADDRESS/CIDR"
        // This regex is specific to matching -j DROP -d <IP> or -j DROP -d <IP/CIDR>
        if (preg_match('/^\s*(\d+)\s+DROP\s+.*?\s+d:([0-9\.\/a-fA-F:]+)/', $line, $matches) || 
            preg_match('/^\s*(\d+)\s+DROP\s+.*?\s+destination\s+([0-9\.\/a-fA-F:]+)/', $line, $matches_alt)) {
            
            $rule_number = isset($matches[1]) ? $matches[1] : $matches_alt[1];
            $ip_address = isset($matches[2]) ? $matches[2] : $matches_alt[2];

            // Validate the extracted IP to prevent showing malformed rules
            if (isValidIpAddress($ip_address)) {
                $blocked_ips[] = ['ip' => $ip_address, 'rule_number' => (int)$rule_number];
            }
        }
    }
    return $blocked_ips;
}


// --- Handle Form Submissions ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] === 'add_ip') {
            $ip_to_block = trim($_POST['ip_address']);
            if (empty($ip_to_block)) {
                $error = "IP address cannot be empty.";
            } elseif (!isValidIpAddress($ip_to_block)) {
                $error = "Invalid IP address or CIDR format.";
            } else {
                // Check if rule already exists to avoid duplicates
                $current_rules = getBlockedIps();
                if (!isset($current_rules['error'])) {
                    foreach ($current_rules as $rule) {
                        if ($rule['ip'] === $ip_to_block) {
                            $error = "IP address {$ip_to_block} is already blocked.";
                            break;
                        }
                    }
                }
                
                if (empty($error)) {
                    // Add the iptables rule. Insert at rule 2 to come after RELATED,ESTABLISHED
                    // This assumes FORWARD policy is DROP.
                    $result = secure_iptables_exec(['-I', 'FORWARD', '2', '-d', $ip_to_block, '-j', 'DROP'], 'add_ip_rule');
                    if (empty($result)) {
                        $message = "IP address {$ip_to_block} blocked successfully.";
                    } else {
                        $error = "Failed to block IP {$ip_to_block}. " . htmlspecialchars($result);
                    }
                }
            }
        } elseif ($_POST['action'] === 'remove_ip') {
            $ip_to_remove = trim($_POST['ip_address']);
            $rule_number = isset($_POST['rule_number']) ? (int)$_POST['rule_number'] : 0;

            if (empty($ip_to_remove) || $rule_number === 0) {
                $error = "Invalid IP address or rule number for removal.";
            } elseif (!isValidIpAddress($ip_to_remove)) {
                $error = "Invalid IP address for removal.";
            } else {
                // It's safer to delete by rule specification rather than line number,
                // as line numbers can shift. But for simplicity of matching `getBlocekdIps`
                // and assuming strict control, rule number is provided.
                // Rule spec: -D FORWARD -d <IP> -j DROP
                $result = secure_iptables_exec(['-D', 'FORWARD', '-d', $ip_to_remove, '-j', 'DROP'], 'remove_ip_rule');
                if (empty($result)) {
                    $message = "IP address {$ip_to_remove} unblocked successfully.";
                } else {
                    $error = "Failed to unblock IP {$ip_to_remove}. " . htmlspecialchars($result);
                }
            }
        }
        // After any iptables change, save rules persistently
        secure_iptables_exec(['-P', 'FORWARD', 'DROP'], 'save_persistent_rules_policy_temp'); // Re-set policy just in case.
        secure_iptables_exec(['-t', 'nat', '-P', 'PREROUTING', 'ACCEPT'], 'save_persistent_rules_policy_temp'); // Re-set policy just in case.
        secure_iptables_exec(['-t', 'nat', '-P', 'POSTROUTING', 'ACCEPT'], 'save_persistent_rules_policy_temp'); // Re-set policy just in case.
        // Save using netfilter-persistent
        secure_iptables_exec(['-L', 'FORWARD'], 'save_persistent_rules'); # This line is incorrect for saving.
        $save_result = shell_exec("sudo /usr/sbin/netfilter-persistent save 2>&1");
        if (!empty(trim($save_result))) {
             error_log("ERROR: netfilter-persistent save failed: " . $save_result);
             $error = ($error ? $error . "\n" : "") . "Failed to save firewall rules persistently: " . htmlspecialchars($save_result);
        }
    }
}

// Reload current blocked IPs after any action
$blocked_ips = getBlockedIps();
if (isset($blocked_ips['error'])) {
    $error = (empty($error) ? "" : $error . "\n") . $blocked_ips['error'];
    $blocked_ips = []; // Clear list on error
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Blocked Sites (IPs)</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        .ip-list-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }
        .ip-list-item:last-child {
            border-bottom: none;
        }
        .ip-list-item span {
            font-family: 'JetBrains Mono', monospace;
            color: #e0e0e0;
        }
        .ip-list-item form {
            margin-bottom: 0; /* Override default form margin */
            flex-direction: row;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Manage Blocked IPs</h1>
        <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>

        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <div class="note">
            <p><i class="fas fa-info-circle"></i> This page allows you to block specific IP addresses by adding <code>iptables</code> DROP rules to the FORWARD chain.</p>
            <p><strong>Note:</strong> Blocking by IP address for services like Google, Facebook, or Cloudflare may block many legitimate websites as they share IP ranges. For domain-based blocking, consider dedicated DNS-level solutions.</p>
            <p>Rules are inserted at position 2 in the FORWARD chain (after <code>RELATED,ESTABLISHED</code>) to ensure blocking is effective.</p>
            <p>Changes are saved persistently.</p>
        </div>

        <h2>Add New Blocked IP</h2>
        <div class="card">
            <form action="manage_blocked_sites.php" method="post">
                <input type="hidden" name="action" value="add_ip">
                <label for="ip_address">IP Address (e.g., 1.2.3.4 or 1.2.3.0/24):</label>
                <input type="text" id="ip_address" name="ip_address" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}(\/(1[6-9]|[2-3][0-2]))?$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$" title="IPv4 (e.g. 1.2.3.4 or 1.2.3.0/24) or IPv6 (e.g. ::1 or 2001:db8::/32)" required>
                <div class="form-actions">
                    <button type="submit" class="button button-add"><i class="fas fa-plus"></i> Block IP</button>
                </div>
            </form>
        </div>

        <h2>Currently Blocked IPs</h2>
        <div class="card">
            <?php if (empty($blocked_ips)): ?>
                <p>No IP addresses currently blocked.</p>
            <?php else: ?>
                <div class="ip-list">
                    <?php foreach ($blocked_ips as $blocked_ip): ?>
                        <div class="ip-list-item">
                            <span><i class="fas fa-ban" style="margin-right: 8px; color: #d9363e;"></i> <?php echo htmlspecialchars($blocked_ip['ip']); ?> (Rule #<?php echo $blocked_ip['rule_number']; ?>)</span>
                            <form action="manage_blocked_sites.php" method="post" onsubmit="return confirm('Are you sure you want to unblock IP \'<?php echo htmlspecialchars($blocked_ip['ip']); ?>\'?');">
                                <input type="hidden" name="action" value="remove_ip">
                                <input type="hidden" name="ip_address" value="<?php echo htmlspecialchars($blocked_ip['ip']); ?>">
                                <input type="hidden" name="rule_number" value="<?php echo $blocked_ip['rule_number']; ?>">
                                <button type="submit" class="button button-remove" style="padding: 5px 10px; font-size: 0.85em;"><i class="fas fa-times"></i> Unblock</button>
                            </form>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
