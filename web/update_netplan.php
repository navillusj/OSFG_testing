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
$ping_path = '/bin/ping'; // Ensure this path is correct based on 'which ping'
$netplan_cmd_path = '/usr/sbin/netplan'; // Ensure this path is correct based on 'which netplan'
$tee_cmd_path = '/usr/bin/tee'; // Ensure this path is correct based on 'which tee'
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
    // Get all interfaces including lo and br0 for full listing, and their operational state
    $command = "{$ip_cmd_path} -o link show | awk -F': ' '{print \$2 \"|\" \$9}'"; // Output: interface_name|operstate
    $output = secure_shell_exec_with_log($command, 'get_all_interfaces_full_with_state');
    if (empty($output) || strpos($output, 'Error:') !== false) {
        return [];
    }
    $interfaces = [];
    foreach (explode("\n", $output) as $line) {
        list($name, $state) = explode('|', $line);
        $interfaces[trim($name)] = trim($state);
    }
    return $interfaces; // Returns associative array: [ 'eth0' => 'UP', 'wlan0' => 'DOWN' ]
}

function get_netplan_interfaces($yq_path, $config_file) {
    $command = "sudo {$yq_path} '.network.ethernets | keys' " . escapeshellarg($config_file);
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
    $command = "sudo {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces[]' " . escapeshellarg($config_file);
    $output = secure_shell_exec_with_log($command, 'get_bridge_interfaces');
    if (empty($output) || strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("yq command failed in get_bridge_interfaces: " . $output);
        return [];
    }
    return array_map('trim', explode("\n", $output));
}

// Add/Remove and Apply functions unchanged for now.
// They are still needed if you decide to re-implement modification later.
function add_interface_to_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    // ... (unchanged) ...
    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);
    $set_ethernet_config = "sudo {$yq_path} '.network.ethernets.{$escaped_interface}.dhcp4 = false' -i {$escaped_config_file}";
    $output = secure_shell_exec_with_log($set_ethernet_config, 'add_interface_ethernet_config');
    if (strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("Error setting ethernet config with yq: " . $output);
        return false;
    }
    $add_to_bridge_cmd = "sudo {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces |= (. + [{$escaped_interface}] | unique)' -i {$escaped_config_file}";
    $output = secure_shell_exec_with_log($add_to_bridge_cmd, 'add_interface_to_bridge');
    return strpos($output, 'Error:') === false && strpos($output, 'sudo:') === false;
}

function remove_interface_from_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    // ... (unchanged) ...
    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);
    $remove_from_bridge_cmd = "sudo {$yq_path} 'del(.network.bridges[\"{$bridge_name}\"].interfaces[] | select(. == {$escaped_interface}))' -i {$escaped_config_file}";
    $output = secure_shell_exec_with_log($remove_from_bridge_cmd, 'remove_interface_from_bridge');
    
    include_once 'config.php';
    $wan_iface = $wan_interface ?? 'UNKNOWN_WAN';

    if ($interface !== 'br0' && $interface !== 'lo' && $interface !== $wan_iface) {
        $remove_from_ethernets_cmd = "sudo {$yq_path} 'del(.network.ethernets[\"{$interface}\"])' -i {$escaped_config_file}";
        secure_shell_exec_with_log($remove_from_ethernets_cmd, 'remove_interface_from_ethernets');
    }
    return strpos($output, 'Error:') === false && strpos($output, 'sudo:') === false;
}

function apply_netplan($netplan_backup_file, $config_file, $netplan_cmd_path, $tee_cmd_path) {
    // ... (unchanged) ...
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
            $all_detected_interfaces_with_state = get_all_detected_interfaces_system($ip_cmd_path); // Get names and operational states
            $configured_interfaces_netplan = get_netplan_interfaces($yq_path, $netplan_config_file); // From ethernets: section
            $bridged_interfaces_names = get_bridge_interfaces($yq_path, $netplan_config_file); // From bridge: interfaces: section

            $interfaces_data = [];
            
            include_once 'config.php';
            $wan_iface = $wan_interface ?? 'UNKNOWN_WAN_FALLBACK';

            // Iterate over all *detected* interfaces to build the comprehensive list
            foreach ($all_detected_interfaces_with_state as $iface_name => $oper_state) {
                $is_wan = ($iface_name === $wan_iface);
                $is_bridged = in_array($iface_name, $bridged_interfaces_names);
                $is_loopback_or_bridge = ($iface_name === 'lo' || $iface_name === 'br0');
                $is_configured_in_netplan = in_array($iface_name, $configured_interfaces_netplan);

                $type = 'Unknown';
                if ($is_loopback_or_bridge) {
                    $type = 'System';
                } elseif ($is_wan) {
                    $type = 'WAN';
                } elseif ($is_bridged) {
                    $type = 'LAN (Bridged)';
                } elseif ($is_configured_in_netplan) { // If configured but not WAN/Bridged
                    $type = 'LAN (Configured)'; // Potentially static IP or other standalone LAN
                } else {
                    $type = 'LAN (Unassigned)'; // Detected but not configured in Netplan
                }
                
                $interfaces_data[] = [
                    'name' => $iface_name,
                    'type' => $type, // Categorical type
                    'oper_state' => $oper_state, // Raw UP/DOWN state
                    'is_wan' => $is_wan,
                    'is_bridged' => $is_bridged,
                    'is_system' => $is_loopback_or_bridge
                ];
            }
            
            usort($interfaces_data, function($a, $b) {
                return strcmp($a['name'], $b['name']);
            });

            echo json_encode(['status' => 'success', 'interfaces' => $interfaces_data]);
            break;

        case 'set_interface_state':
            $interface = isset($_POST['interface']) ? trim($_POST['interface']) : '';
            $state = isset($_POST['state']) ? trim($_POST['state']) : ''; // 'up' or 'down'

            if (empty($interface) || !in_array($state, ['up', 'down'])) {
                echo json_encode(['status' => 'error', 'message' => 'Invalid interface or state provided.']);
                exit();
            }

            // Security: Prevent disabling critical interfaces like WAN or br0 if it's the only one
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

            if (empty(trim($output))) { // Command successful if output is empty
                echo json_encode(['status' => 'success', 'message' => "Interface '{$interface}' set to '{$state}' successfully."]);
            } else {
                echo json_encode(['status' => 'error', 'message' => "Failed to set interface '{$interface}' to '{$state}': " . htmlspecialchars($output)]);
            }
            break;

        // Add/remove bridge actions remain, but not directly used by current settings.php UI
        case 'add_to_bridge': // ... (unchanged) ...
        case 'remove_from_bridge': // ... (unchanged) ...

        default:
            echo json_encode(['status' => 'error', 'message' => 'Invalid action.']);
            break;
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'No action specified for update_netplan.php.']);
}
exit();
?>
