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

function get_all_detected_interfaces_system() {
    // This is from `ip link show`, excluding loopback
    $command = "ip -o link show | awk -F': ' '{print \$2}' | grep -v 'lo'";
    $output = secure_shell_exec_with_log($command, 'get_all_interfaces');
    if (empty($output) || strpos($output, 'Error:') !== false) {
        return [];
    }
    return array_map('trim', explode(' ', $output));
}

function get_netplan_interfaces($yq_path, $config_file) {
    $command = "sudo {$yq_path} '.network.ethernets | keys' " . escapeshellarg($config_file);
    $output = secure_shell_exec_with_log($command, 'get_defined_interfaces');
    if (empty($output) || strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("yq command failed in get_netplan_interfaces: " . $output);
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

function add_interface_to_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);

    // 1. Ensure interface exists in 'ethernets' section with dhcp4: no
    // This will create the entry if it doesn't exist.
    $set_ethernet_config = "sudo {$yq_path} '.network.ethernets.{$escaped_interface}.dhcp4 = false' -i {$escaped_config_file}";
    $output = secure_shell_exec_with_log($set_ethernet_config, 'add_interface_ethernet_config');
    if (strpos($output, 'Error:') !== false || strpos($output, 'sudo:') !== false) {
        error_log("Error setting ethernet config with yq: " . $output);
        return false;
    }

    // 2. Add interface to bridge array (only if not already there and unique)
    $add_to_bridge_cmd = "sudo {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces |= (. + [{$escaped_interface}] | unique)' -i {$escaped_config_file}";
    $output = secure_shell_exec_with_log($add_to_bridge_cmd, 'add_interface_to_bridge');
    return strpos($output, 'Error:') === false && strpos($output, 'sudo:') === false;
}

function remove_interface_from_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);

    // Remove interface from bridge array
    $remove_from_bridge_cmd = "sudo {$yq_path} 'del(.network.bridges[\"{$bridge_name}\"].interfaces[] | select(. == {$escaped_interface}))' -i {$escaped_config_file}";
    $output = secure_shell_exec_with_log($remove_from_bridge_cmd, 'remove_interface_from_bridge');
    
    // After removing from bridge, remove it from the 'ethernets' section too
    // UNLESS it's the WAN interface, loopback, or the bridge itself (br0).
    include_once 'config.php'; // Ensure wan_interface is loaded
    $wan_iface = $wan_interface ?? 'UNKNOWN_WAN'; // Fallback for safety

    if ($interface !== 'br0' && $interface !== 'lo' && $interface !== $wan_iface) {
        $remove_from_ethernets_cmd = "sudo {$yq_path} 'del(.network.ethernets[\"{$interface}\"])' -i {$escaped_config_file}";
        secure_shell_exec_with_log($remove_from_ethernets_cmd, 'remove_interface_from_ethernets');
    }

    return strpos($output, 'Error:') === false && strpos($output, 'sudo:') === false;
}

function apply_netplan($netplan_backup_file, $config_file, $netplan_cmd_path, $tee_cmd_path) {
    $escaped_config_file = escapeshellarg($config_file);
    $escaped_netplan_backup_file = escapeshellarg($netplan_backup_file);

    // Try PHP copy for backup first. If it fails (permissions), try sudo tee as fallback.
    if (file_exists($config_file)) {
        $backup_success = copy($config_file, $netplan_backup_file);
        if (!$backup_success) {
            error_log("PHP copy failed for backup. Attempting with sudo tee for: {$config_file} to {$netplan_backup_file}");
            $backup_cmd = "sudo {$tee_cmd_path} {$escaped_netplan_backup_file} < {$escaped_config_file} > /dev/null 2>&1";
            $backup_output = secure_shell_exec_with_log($backup_cmd, 'netplan_backup_tee');
            if (!empty(trim($backup_output)) && strpos($backup_output, 'sudo:') !== false) { // Also check for sudo errors here
                error_log("Sudo tee backup failed as well: " . $backup_output);
                return ['status' => 'error', 'message' => 'Failed to create backup of current Netplan config. (Backup command failed: ' . trim($backup_output) . ')'];
            }
        }
    }

    // Apply new config
    $apply_command = "sudo {$netplan_cmd_path} apply 2>&1";
    $apply_output = secure_shell_exec_with_log($apply_command, 'netplan_apply');

    if ($apply_output === null || !empty(trim($apply_output))) {
        // If apply fails, attempt to revert from backup
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
            $all_detected_interfaces = get_all_detected_interfaces_system();
            $bridged_interfaces = get_bridge_interfaces($yq_path, $netplan_config_file);

            // Prepare interfaces for the single dropdown
            $interfaces_for_dropdown = [];
            foreach ($all_detected_interfaces as $iface) {
                if ($iface === 'lo' || $iface === 'br0') {
                    continue; // Skip loopback and the bridge itself
                }
                
                include_once 'config.php'; // Ensure wan_interface is loaded for accurate WAN detection
                $wan_iface_from_config = $wan_interface ?? 'UNKNOWN_WAN_FALLBACK';

                $is_wan = ($iface === $wan_iface_from_config);
                $is_bridged = in_array($iface, $bridged_interfaces);

                $label = $iface;
                if ($is_wan) {
                    $label .= " (WAN)";
                }
                if ($is_bridged) {
                    $label .= " (Bridged)";
                }

                $interfaces_for_dropdown[] = [
                    'name' => $iface,
                    'label' => $label,
                    'is_wan' => $is_wan,
                    'is_bridged' => $is_bridged
                ];
            }
            
            // Sort by name
            usort($interfaces_for_dropdown, function($a, $b) {
                return strcmp($a['name'], $b['name']);
            });

            echo json_encode(['status' => 'success', 'interfaces' => $interfaces_for_dropdown, 'in_bridge' => $bridged_interfaces]);
            break;

        case 'add_to_bridge':
            $interface = isset($_POST['interface']) ? trim($_POST['interface']) : '';
            if (empty($interface)) {
                echo json_encode(['status' => 'error', 'message' => 'No interface specified.']);
                exit();
            }
            // Basic validation: Prevent adding br0 to itself or WAN to bridge
            include_once 'config..php';
            $wan_iface_from_config = $wan_interface ?? 'UNKNOWN_WAN';
            if ($interface === 'br0' || $interface === 'lo' || $interface === $wan_iface_from_config) {
                 echo json_encode(['status' => 'error', 'message' => "Cannot add '{$interface}' to the bridge. It's either loopback, the bridge itself, or the WAN interface."]);
                 exit();
            }

            $current_bridged_interfaces = get_bridge_interfaces($yq_path, $netplan_config_file);
            if (in_array($interface, $current_bridged_interfaces)) {
                echo json_encode(['status' => 'error', 'message' => "Interface '{$interface}' is already in the bridge (br0)."]);
                exit();
            }

            if (add_interface_to_bridge($yq_path, $netplan_config_file, $interface)) {
                echo json_encode(apply_netplan($netplan_backup_file, $netplan_config_file, $netplan_cmd_path, $tee_cmd_path));
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Failed to update Netplan YAML for adding interface. Check logs for details.']);
            }
            break;

        case 'remove_from_bridge':
            $interface = isset($_POST['interface']) ? trim($_POST['interface']) : '';
            if (empty($interface)) {
                echo json_encode(['status' => 'error', 'message' => 'No interface specified.']);
                exit();
            }

            // Basic validation: Prevent removing WAN interface
            include_once 'config.php';
            $wan_iface_from_config = $wan_interface ?? 'UNKNOWN_WAN';
            if ($interface === $wan_iface_from_config) {
                 echo json_encode(['status' => 'error', 'message' => "Cannot remove WAN interface ('{$interface}') from the bridge."]);
                 exit();
            }

            $current_bridged_interfaces = get_bridge_interfaces($yq_path, $netplan_config_file);
            if (!in_array($interface, $current_bridged_interfaces)) {
                echo json_encode(['status' => 'error', 'message' => "Interface '{$interface}' is not currently in the bridge (br0)."]);
                exit();
            }

            if (remove_interface_from_bridge($yq_path, $netplan_config_file, $interface)) {
                echo json_encode(apply_netplan($netplan_backup_file, $netplan_config_file, $netplan_cmd_path, $tee_cmd_path));
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Failed to update Netplan YAML for removing interface. Check logs for details.']);
            }
            break;

        default:
            echo json_encode(['status' => 'error', 'message' => 'Invalid action.']);
            break;
    }
} else {
    echo json_encode(['status' => 'error', 'message' => 'No action specified for update_netplan.php.']);
}
exit();
?>
