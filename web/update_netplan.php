<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized access.']);
    exit();
}

$netplan_config_file = '/etc/netplan/01-network-config.yaml';
$netplan_backup_file = '/etc/netplan/01-network-config.yaml.bak';
$yq_path = '/usr/local/bin/yq'; // Ensure this path is correct based on 'which yq'
$ping_path = '/bin/ping';
$netplan_cmd_path = '/usr/sbin/netplan';
$tee_cmd_path = '/usr/bin/tee';
$ip_cmd_path = '/usr/sbin/ip'; // Path for ip command

function secure_shell_exec_with_log($command, $log_context = 'netplan_mgmt') {
    error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $command));
    $output = shell_exec($command . ' 2>&1');
    if ($output === null) {
        error_log(sprintf("[%s] ERROR: Command failed for %s. Command: '%s' - Output: '%s'", date('Y-m-d H:i:s'), $log_context, $command, $output));
        return "Error: Command failed or not found.";
    }
    return trim($output);
}

// --- Helper Functions to Interact with Netplan YAML using yq ---

function get_all_detected_interfaces_system($ip_cmd_path) {
    // --- REVISED AWK PARSING FOR IP LINK SHOW ---
    // This command gets multi-line output then processes it to extract fields more reliably.
    // It specifically looks for 'state', 'RX: bytes', and 'TX: bytes' lines.
    $command = "{$ip_cmd_path} -s link show"; // Use non-one-line output for easier multi-line parsing
    $raw_output = secure_shell_exec_with_log($command, 'get_all_interfaces_full_with_state_and_traffic_raw');
    
    error_log(sprintf("[%s] DEBUG: Raw ip link show output:\n%s", date('Y-m-d H:i:s'), $raw_output));

    if (empty($raw_output) || strpos($raw_output, 'Error:') !== false) {
        return [];
    }

    $interfaces = [];
    $lines = explode("\n", $raw_output);
    $current_iface_name = null;
    $current_iface_data = ['oper_state' => 'UNKNOWN', 'rx_bytes' => 0, 'tx_bytes' => 0];

    foreach ($lines as $line) {
        $line = trim($line);

        // Match interface start line: e.g., "1: lo: <LOOPBACK,UP,LOWER_UP>"
        if (preg_match('/^\d+:\s+([a-zA-Z0-9_]+):.*$/', $line, $matches)) {
            // If we have data for a previous interface, save it
            if ($current_iface_name !== null) {
                $interfaces[$current_iface_name] = $current_iface_data;
            }
            // Start new interface data
            $current_iface_name = $matches[1];
            $current_iface_data = ['oper_state' => 'UNKNOWN', 'rx_bytes' => 0, 'tx_bytes' => 0];

            // Extract oper_state from this line too if present (e.g., 'state UP')
            if (preg_match('/state\s+([A-Z_]+)/', $line, $state_matches)) {
                $current_iface_data['oper_state'] = $state_matches[1];
            }
        } 
        // Match RX bytes line: e.g., "RX: bytes packets errors dropped missed mcast"
        elseif (str_starts_with($line, 'RX:')) {
            if (preg_match('/RX:\s+bytes\s+(\d+)/', $line, $matches)) {
                $current_iface_data['rx_bytes'] = (int)$matches[1];
            }
        }
        // Match TX bytes line: e.g., "TX: bytes packets errors dropped carrier collsns"
        elseif (str_starts_with($line, 'TX:')) {
            if (preg_match('/TX:\s+bytes\s+(\d+)/', $line, $matches)) {
                $current_iface_data['tx_bytes'] = (int)$matches[1];
            }
        }
    }

    // Save the last interface's data
    if ($current_iface_name !== null) {
        $interfaces[$current_iface_name] = $current_iface_data;
    }

    error_log(sprintf("[%s] DEBUG: Parsed interfaces data (from ip link show):\n%s", date('Y-m-d H:i:s'), json_encode($interfaces, JSON_PRETTY_PRINT))); // DEBUG LOG
    return $interfaces;
}

function get_netplan_interfaces($yq_path, $config_file) {
    // --- REVISED YQ CALLING APPROACH FOR RELIABILITY ---
    // Instead of piping directly into sudo yq, read file content, pass to yq via stdin
    // This can sometimes bypass tty issues with sudo + piping.
    $config_content = @file_get_contents($config_file); // @ suppresses warnings if file not readable by PHP directly
    if ($config_content === false) {
        error_log("Failed to read Netplan config file: {$config_file}");
        return [];
    }

    $command = "echo " . escapeshellarg($config_content) . " | sudo {$yq_path} '.network.ethernets | keys' 2>&1"; // Changed: now pipes content to yq
    $output = secure_shell_exec_with_log($command, 'get_defined_interfaces');
    
    if (empty($output) || strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("yq command failed in get_defined_interfaces: " . $output);
        return [];
    }
    $interfaces = [];
    foreach (explode("\n", $output) as $line) {
        if (strpos($line, '-') === 0) {
            $interfaces[] = trim(substr($line, 1));
        }
    }
    return $interfaces;
}

function get_bridge_interfaces($yq_path, $config_file, $bridge_name = 'br0') {
    // --- REVISED YQ CALLING APPROACH FOR RELIABILITY ---
    $config_content = @file_get_contents($config_file);
    if ($config_content === false) {
        error_log("Failed to read Netplan config file for bridge interfaces: {$config_file}");
        return [];
    }
    $command = "echo " . escapeshellarg($config_content) . " | sudo {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces[]' 2>&1"; // Changed
    $output = secure_shell_exec_with_log($command, 'get_bridge_interfaces');
    
    if (empty($output) || strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("yq command failed in get_bridge_interfaces: " . $output);
        return [];
    }
    return array_map('trim', explode("\n", $output));
}

// Add/Remove and Apply functions (unchanged logic, but simplified yq calls for in-place edit)
function add_interface_to_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);

    // Using `yq -i` directly, which edits in-place. This usually works well with sudoers.
    $set_ethernet_config = "sudo {$yq_path} '.network.ethernets.{$escaped_interface}.dhcp4 = false' -i {$escaped_config_file} 2>&1";
    $output = secure_shell_exec_with_log($set_ethernet_config, 'add_interface_ethernet_config');
    if (strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false || !empty(trim($output))) {
        error_log("Error setting ethernet config with yq: " . $output);
        return false;
    }

    $add_to_bridge_cmd = "sudo {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces |= (. + [{$escaped_interface}] | unique)' -i {$escaped_config_file} 2>&1";
    $output = secure_shell_exec_with_log($add_to_bridge_cmd, 'add_interface_to_bridge');
    return strpos($output, 'Error:') === false && strpos($output, 'sudo:') === false && empty(trim($output));
}

function remove_interface_from_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);

    $remove_from_bridge_cmd = "sudo {$yq_path} 'del(.network.bridges[\"{$bridge_name}\"].interfaces[] | select(. == {$escaped_interface}))' -i {$escaped_config_file} 2>&1";
    $output = secure_shell_exec_with_log($remove_from_bridge_cmd, 'remove_interface_from_bridge');
    
    include_once 'config.php';
    $wan_iface = $wan_interface ?? 'UNKNOWN_WAN';

    if ($interface !== 'br0' && $interface !== 'lo' && $interface !== $wan_iface) {
        $remove_from_ethernets_cmd = "sudo {$yq_path} 'del(.network.ethernets[\"{$interface}\"])' -i {$escaped_config_file} 2>&1";
        secure_shell_exec_with_log($remove_from_ethernets_cmd, 'remove_interface_from_ethernets');
    }
    return strpos($output, 'Error:') === false && strpos($output, 'sudo:') === false && empty(trim($output));
}

function apply_netplan($netplan_backup_file, $config_file, $netplan_cmd_path, $tee_cmd_path) {
    $escaped_config_file = escapeshellarg($config_file);
    $escaped_netplan_backup_file = escapeshellarg($netplan_backup_file);

    if (file_exists($config_file)) {
        $backup_success = copy($config_file, $netplan_backup_file);
        if (!$backup_success) {
            error_log("PHP copy failed for backup. Attempting with sudo tee for: {$config_file} to {$netplan_backup_file}");
            $backup_cmd = "sudo {$tee_cmd_path} {$escaped_netplan_backup_file} < {$escaped_config_file} > /dev/null 2>&1";
            $backup_output = secure_shell_exec_with_log($backup_cmd, 'netplan_backup_tee');
            if (!empty(trim($backup_output)) && strpos($backup_output, 'sudo:') !== false) {
                error_log("Sudo tee backup failed as well: " . $backup_output);
                return ['status' => 'error', 'message' => 'Failed to create backup of current Netplan config. (Backup command failed: ' . trim($backup_output) . ')'];
            }
        }
    }
    $apply_command = "sudo {$netplan_cmd_path} apply 2>&1";
    $apply_output = secure_shell_exec_with_log($apply_command, 'netplan_apply');

    if ($apply_output === null || !empty(trim($apply_output))) {
        error_log("Netplan apply failed. Attempting to revert: " . trim($apply_output));
        if (file_exists($netplan_backup_file)) {
            $revert_command = "sudo {$tee_cmd_path} {$escaped_config_file} < {$escaped_netplan_backup_file} > /dev/null 2>&1 && sudo {$netplan_cmd_path} apply 2>&1";
            $revert_output = secure_shell_exec_with_log($revert_command, 'netplan_revert');
            $revert_message = "Attempted to revert from backup. Revert output: " . trim($revert_output);
        } else {
            $revert_message = "No backup found to revert to.";
        }
        return ['status' => 'error', 'message' => 'Failed to apply Netplan config: ' . trim($apply_output) . "\n" . $revert_message];
    }
    return ['status' => 'success', 'message' => 'Netplan configuration updated and applied successfully!'];
}


// --- API Endpoints ---
if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'get_interfaces':
            $all_detected_interfaces_full_data = get_all_detected_interfaces_system($ip_cmd_path);
            $configured_interfaces_netplan = get_netplan_interfaces($yq_path, $netplan_config_file); // This is failing based on logs
            $bridged_interfaces_names = get_bridge_interfaces($yq_path, $netplan_config_file); // This is failing based on logs

            $interfaces_data = [];
            
            include_once 'config.php';
            $wan_iface = $wan_interface ?? 'UNKNOWN_WAN_FALLBACK';

            foreach ($all_detected_interfaces_full_data as $iface_name => $traffic_data) {
                $oper_state = $traffic_data['oper_state'];
                $rx_bytes = $traffic_data['rx_bytes'];
                $tx_bytes = $traffic_data['tx_bytes'];

                $is_wan = ($iface_name === $wan_iface);
                $is_bridged = in_array($iface_name, $bridged_interfaces_names);
                $is_loopback_or_bridge_itself = ($iface_name === 'lo' || $iface_name === 'br0');
                $is_configured_in_netplan = in_array($iface_name, $configured_interfaces_netplan);

                $type_label = 'Unknown';
                if ($is_loopback_or_bridge_itself) {
                    $type_label = 'System';
                } elseif ($is_wan) {
                    $type_label = 'WAN';
                } elseif ($is_bridged) {
                    $type_label = 'LAN (Bridged)';
                } elseif ($is_configured_in_netplan) {
                    $type_label = 'LAN (Configured)';
                } else {
                    $type_label = 'LAN (Unassigned)';
                }
                
                $interfaces_data[] = [
                    'name' => $iface_name,
                    'type_label' => $type_label,
                    'oper_state' => strtoupper($oper_state),
                    'rx_bytes' => $rx_bytes,
                    'tx_bytes' => $tx_bytes,
                    'is_wan' => $is_wan,
                    'is_bridged' => $is_bridged,
                    'is_system' => $is_loopback_or_bridge_itself
                ];
            }
            
            usort($interfaces_data, function($a, $b) {
                return strcmp($a['name'], $b['name']);
            });

            echo json_encode(['status' => 'success', 'interfaces' => $interfaces_data]);
            break;

        case 'set_interface_state':
            $interface = isset($_POST['interface']) ? trim($_POST['interface']) : '';
            $state = isset($_POST['state']) ? trim($_POST['state']) : '';

            if (empty($interface) || !in_array($state, ['up', 'down'])) {
                echo json_encode(['status' => 'error', 'message' => 'Invalid interface or state provided.']);
                exit();
            }

            include_once 'config.php';
            $wan_iface = $wan_interface ?? 'UNKNOWN_WAN';
            if ($interface === $wan_iface && $state === 'down') {
                echo json_encode(['status' => 'error', 'message' => "Cannot disable WAN interface ('{$interface}'). This may disrupt internet access."]);
                exit();
            }
            if ($interface === 'br0' && $state === 'down') {
                echo json_encode(['status' => 'error', 'message' => "Cannot disable the main bridge interface ('{$interface}'). This will sever all LAN connectivity."]);
                exit();
            }
            if ($interface === 'lo' && $state === 'down') {
                echo json_encode(['status' => 'error', 'message' => "Cannot disable loopback interface ('{$interface}')."]);
                exit();
            }

            $command = "sudo {$ip_cmd_path} link set " . escapeshellarg($interface) . " {$state} 2>&1";
            $output = secure_shell_exec_with_log($command, 'set_interface_state');

            if (empty(trim($output))) {
                echo json_encode(['status' => 'success', 'message' => "Interface '{$interface}' set to '{$state}' successfully."]);
            } else {
                echo json_encode(['status' => 'error', 'message' => "Failed to set interface '{$interface}' to '{$state}': " . htmlspecialchars($output)]);
            }
            break;

        case 'add_to_bridge':
        case 'remove_from_bridge':
        default:
            echo json_encode(['status' => 'error', 'message' => 'Invalid action.']);
            break;
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'No action specified for update_netplan.php.']);
}
exit();
?>
