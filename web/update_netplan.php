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
$yq_path = '/usr/local/bin/yq';
$ping_path = '/bin/ping';
$netplan_cmd_path = '/usr/sbin/netplan';
$tee_cmd_path = '/usr/bin/tee';
$ip_cmd_path = '/usr/sbin/ip';
$sudo_cmd_path = '/usr/bin/sudo';

function secure_shell_exec_with_log($command, $log_context = 'general') {
    global $sudo_cmd_path;

    $full_command = $command;
    // Ensure sudo is called with its full path if present
    if (str_starts_with($command, 'sudo ') && !str_starts_with($command, "{$sudo_cmd_path}")) {
        $full_command = "{$sudo_cmd_path} " . substr($command, 5);
    } elseif (str_starts_with($command, "{$sudo_cmd_path}") && strpos($command, ' ') === false) { // Handle just "sudo" as command
        $full_command = $sudo_cmd_path;
    }

    error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $full_command));
    
    $output_lines = [];
    $return_var = 0;
    exec($full_command . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);

    error_log(sprintf("[%s] DEBUG: Raw output for command '%s': '%s'", date('Y-m-d H:i:s'), $full_command, $output));
    error_log(sprintf("[%s] DEBUG: Return variable for command '%s': %d", date('Y-m-d H:i:s'), $full_command, $return_var));

    if ($return_var !== 0) {
        error_log(sprintf("[%s] ERROR: Command failed for %s. Return var: %d. Command: '%s'. Output: '%s'", date('Y-m-d H:i:s'), $log_context, $return_var, $full_command, $output));
        return "Error: Command exited with status {$return_var}: " . $output;
    }
    
    $trimmed_output = trim($output);
    if (!empty($trimmed_output) && strpos($trimmed_output, 'sudo:') === false && strpos($trimmed_output, 'This incident will be reported') === false) {
        error_log(sprintf("[%s] WARNING: Command '%s' produced unexpected output on success: '%s'", date('Y-m-d H:i:s'), $full_command, $trimmed_output));
        return $trimmed_output;
    }
    
    return '';
}

function get_all_detected_interfaces_system($ip_cmd_path) {
    $command = "{$ip_cmd_path} -s link show";
    $raw_output = shell_exec($command . ' 2>&1'); 
    
    error_log(sprintf("[%s] DEBUG: Raw ip -s link show output for parsing:\n%s", date('Y-m-d H:i:s'), $raw_output));

    if ($raw_output === null) {
        error_log(sprintf("[%s] ERROR: ip -s link show command failed (shell_exec returned NULL): %s", date('Y-m-d H:i:s'), $raw_output));
        return [];
    }
    if (strpos($raw_output, 'Error:') !== false || !empty(trim($raw_output)) && (strpos(trim($raw_output), 'command not found') !== false || strpos(trim($raw_output), 'Operation not permitted') !== false)) {
        error_log(sprintf("[%s] ERROR: ip -s link show command produced error output: %s", date('Y-m-d H:i:s'), $raw_output));
        return [];
    }

    $interfaces = [];
    $lines = explode("\n", $raw_output);
    $current_iface_name = null;
    $current_iface_data = ['oper_state' => 'UNKNOWN', 'rx_bytes' => 0, 'tx_bytes' => 0];

    foreach ($lines as $line) {
        $line = trim($line);

        if (preg_match('/^\d+:\s+([a-zA-Z0-9_.-]+):\s+.*?state\s+([A-Z_]+).*$/', $line, $matches)) {
            if ($current_iface_name !== null) {
                $interfaces[$current_iface_name] = $current_iface_data;
                error_log(sprintf("[%s] DEBUG: Finished parsing %s data: %s", date('Y-m-d H:i:s'), $current_iface_name, json_encode($current_iface_data)));
            }
            $current_iface_name = $matches[1];
            $current_iface_data = [
                'oper_state' => $matches[2],
                'rx_bytes' => 0, 
                'tx_bytes' => 0
            ];
            error_log(sprintf("[%s] DEBUG: Started parsing interface %s with initial state %s", date('Y-m-d H:i:s'), $current_iface_name, $current_iface_data['oper_state']));
        } 
        elseif (str_starts_with($line, 'RX:')) {
            if (preg_match('/bytes\s+(\d+)/', $line, $matches)) {
                if ($current_iface_name !== null) {
                    $current_iface_data['rx_bytes'] = (int)$matches[1];
                    error_log(sprintf("[%s] DEBUG: Parsed RX bytes for %s: %d", date('Y-m-d H:i:s'), $current_iface_name, $current_iface_data['rx_bytes']));
                }
            } else {
                 $next_line_index = array_search($line, $lines) + 1;
                 if (isset($lines[$next_line_index]) && preg_match('/^\s*(\d+)\s+.*$/', $lines[$next_line_index], $matches_next)) {
                    if ($current_iface_name !== null) {
                        $current_iface_data['rx_bytes'] = (int)$matches_next[1];
                        error_log(sprintf("[%s] DEBUG: Parsed RX bytes (next line) for %s: %d", date('Y-m-d H:i:s'), $current_iface_name, $current_iface_data['rx_bytes']));
                    }
                 }
            }
        }
        elseif (str_starts_with($line, 'TX:')) {
            if (preg_match('/bytes\s+(\d+)/', $line, $matches)) {
                if ($current_iface_name !== null) {
                    $current_iface_data['tx_bytes'] = (int)$matches[1];
                    error_log(sprintf("[%s] DEBUG: Parsed TX bytes for %s: %d", date('Y-m-d H:i:s'), $current_iface_name, $current_iface_data['tx_bytes']));
                }
            } else {
                $next_line_index = array_search($line, $lines) + 1;
                if (isset($lines[$next_line_index]) && preg_match('/^\s*(\d+)\s+.*$/', $lines[$next_line_index], $matches_next)) {
                    if ($current_iface_name !== null) {
                        $current_iface_data['tx_bytes'] = (int)$matches_next[1];
                        error_log(sprintf("[%s] DEBUG: Parsed TX bytes (next line) for %s: %d", date('Y-m-d H:i:s'), $current_iface_name, $current_iface_data['tx_bytes']));
                    }
                }
            }
        }
    }

    if ($current_iface_name !== null) {
        $interfaces[$current_iface_name] = $current_iface_data;
        error_log(sprintf("[%s] DEBUG: Finished parsing last interface %s data: %s", date('Y-m-d H:i:s'), $current_iface_name, json_encode($interfaces, JSON_PRETTY_PRINT)));
    }

    return $interfaces;
}

function get_netplan_interfaces($yq_path, $config_file) {
    global $sudo_cmd_path;

    $config_content = @file_get_contents($config_file);
    if ($config_content === false) {
        error_log("Failed to read Netplan config file: {$config_file}");
        return [];
    }

    $output_lines = []; $return_var = 0;
    $command_str = "{$sudo_cmd_path} {$yq_path} '.network.ethernets | keys' " . escapeshellarg($config_file); // Pass file directly
    
    error_log(sprintf("[%s] DEBUG: Executing yq get_defined_interfaces command: %s", date('Y-m-d H:i:s'), $command_str));
    exec($command_str . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);
    
    error_log(sprintf("[%s] DEBUG: get_defined_interfaces yq output: '%s', return_var: %d", date('Y-m-d H:i:s'), $output, $return_var));

    if ($return_var !== 0) {
        error_log("yq command failed in get_defined_interfaces (return_var {$return_var}): " . $output);
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
    global $sudo_cmd_path;

    $config_content = @file_get_contents($config_file);
    if ($config_content === false) {
        error_log("Failed to read Netplan config file for bridge interfaces: {$config_file}");
        return [];
    }
    $output_lines = []; $return_var = 0;
    $command_str = "{$sudo_cmd_path} {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces[]' " . escapeshellarg($config_file); // Pass file directly
    
    error_log(sprintf("[%s] DEBUG: Executing yq get_bridge_interfaces command: %s", date('Y-m-d H:i:s'), $command_str));
    exec($command_str . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);
    
    error_log(sprintf("[%s] DEBUG: get_bridge_interfaces yq output: '%s', return_var: %d", date('Y-m-d H:i:s'), $output, $return_var));

    if ($return_var !== 0) {
        error_log("yq command failed in get_bridge_interfaces (return_var {$return_var}): " . $output);
        return [];
    }
    return array_map('trim', explode("\n", $output));
}

function add_interface_to_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    global $sudo_cmd_path;

    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);
    $output_lines = []; $return_var = 0;

    $command = "{$sudo_cmd_path} {$yq_path} '.network.ethernets.{$escaped_interface}.dhcp4 = false' -i {$escaped_config_file}";
    error_log(sprintf("[%s] DEBUG: Executing yq add_interface_ethernet_config: %s", date('Y-m-d H:i:s'), $command));
    exec($command . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);
    if ($return_var !== 0) {
        error_log("Error setting ethernet config with yq (return_var {$return_var}): " . $output);
        return false;
    }

    $command = "{$sudo_cmd_path} {$yq_path} '.network.bridges[\"{$bridge_name}\"].interfaces |= (. + [{$escaped_interface}] | unique)' -i {$escaped_config_file}";
    error_log(sprintf("[%s] DEBUG: Executing yq add_interface_to_bridge: %s", date('Y-m-d H:i:s'), $command));
    exec($command . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);
    if ($return_var !== 0) {
        error_log("Error adding to bridge with yq (return_var {$return_var}): " . $output);
        return false;
    }
    return true;
}

function remove_interface_from_bridge($yq_path, $config_file, $interface, $bridge_name = 'br0') {
    global $sudo_cmd_path;

    $escaped_interface = escapeshellarg($interface);
    $escaped_config_file = escapeshellarg($config_file);
    $output_lines = []; $return_var = 0;

    $command = "{$sudo_cmd_path} {$yq_path} 'del(.network.bridges[\"{$bridge_name}\"].interfaces[] | select(. == {$escaped_interface}))' -i {$escaped_config_file}";
    error_log(sprintf("[%s] DEBUG: Executing yq remove_interface_from_bridge: %s", date('Y-m-d H:i:s'), $command));
    exec($command . ' 2>&1', $output_lines, $return_var);
    $output = implode("\n", $output_lines);
    if ($return_var !== 0) {
        error_log("Error removing from bridge with yq (return_var {$return_var}): " . $output);
        return false;
    }
    
    include_once 'config.php';
    $wan_iface = $wan_interface ?? 'UNKNOWN_WAN';

    if ($interface !== 'br0' && $interface !== 'lo' && $interface !== $wan_iface) {
        $command = "{$sudo_cmd_path} {$yq_path} 'del(.network.ethernets[\"{$interface}\"])' -i {$escaped_config_file}";
        error_log(sprintf("[%s] DEBUG: Executing yq remove_interface_from_ethernets: %s", date('Y-m-d H:i:s'), $command));
        $output_ethernets_lines = []; $return_var_ethernets = 0;
        exec($command . ' 2>&1', $output_ethernets_lines, $return_var_ethernets);
        $output_ethernets = implode("\n", $output_ethernets_lines);
        if ($return_var_ethernets !== 0) {
             error_log("Error removing from ethernets with yq (return_var {$return_var_ethernets}): " . $output_ethernets);
        }
    }
    return true;
}

function apply_netplan($netplan_backup_file, $config_file, $netplan_cmd_path, $tee_cmd_path) {
    global $sudo_cmd_path;

    $escaped_config_file = escapeshellarg($config_file);
    $escaped_netplan_backup_file = escapeshellarg($netplan_backup_file);
    $output_lines = []; $return_var = 0;

    if (file_exists($config_file)) {
        $backup_success = copy($config_file, $netplan_backup_file);
        if (!$backup_success) {
            error_log("PHP copy failed for backup. Attempting with sudo tee for: {$config_file} to {$netplan_backup_file}");
            $command = "{$sudo_cmd_path} {$tee_cmd_path} {$escaped_netplan_backup_file} < {$escaped_config_file} > /dev/null";
            error_log(sprintf("[%s] DEBUG: Executing tee backup command: %s", date('Y-m-d H:i:s'), $command));
            exec($command, $output_lines, $return_var);
            $output_backup = implode("\n", $output_lines);
            if ($return_var !== 0) {
                error_log("Sudo tee backup failed (return_var {$return_var}): " . $output_backup);
                return ['status' => 'error', 'message' => 'Failed to create backup of current Netplan config. (Backup command failed: ' . trim($output_backup) . ')'];
            }
        }
    }
    $command = "{$sudo_cmd_path} {$netplan_cmd_path} apply";
    error_log(sprintf("[%s] DEBUG: Executing netplan apply command: %s", date('Y-m-d H:i:s'), $command));
    exec($command . ' 2>&1', $output_lines, $return_var);
    $apply_output = implode("\n", $output_lines);

    if ($return_var !== 0) {
        error_log("Netplan apply failed (return_var {$return_var}). Attempting to revert: " . trim($apply_output));
        if (file_exists($netplan_backup_file)) {
            $command = "{$sudo_cmd_path} {$tee_cmd_path} {$escaped_config_file} < {$escaped_netplan_backup_file} > /dev/null && {$sudo_cmd_path} {$netplan_cmd_path} apply";
            error_log(sprintf("[%s] DEBUG: Executing netplan revert command: %s", date('Y-m-d H:i:s'), $command));
            $revert_output_lines = []; $revert_return_var = 0;
            exec($command . ' 2>&1', $revert_output_lines, $revert_return_var);
            $revert_output = implode("\n", $revert_output_lines);
            $revert_message = "Attempted to revert from backup. Revert output: " . trim($revert_output) . " (status: {$revert_return_var})";
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
            $configured_interfaces_netplan = get_netplan_interfaces($yq_path, $netplan_config_file);
            $bridged_interfaces_names = get_bridge_interfaces($yq_path, $netplan_config_file);

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

            $command = "{$sudo_cmd_path} {$ip_cmd_path} link set " . escapeshellarg($interface) . " {$state}";
            $output_error_message = secure_shell_exec_with_log($command, 'set_interface_state');

            if (empty($output_error_message)) {
                echo json_encode(['status' => 'success', 'message' => "Interface '{$interface}' set to '{$state}' successfully."]);
            } else {
                echo json_encode(['status' => 'error', 'message' => "Failed to set interface '{$interface}' to '{$state}': " . htmlspecialchars($output_error_message)]);
            }
            break;

        case 'set_bridge_membership':
            $interface = isset($_POST['interface']) ? trim($_POST['interface']) : '';
            $action = isset($_POST['action_type']) ? trim($_POST['action_type']) : '';

            if (empty($interface) || !in_array($action, ['add', 'remove'])) {
                echo json_encode(['status' => 'error', 'message' => 'Invalid interface or action provided.']);
                exit();
            }

            include_once 'config.php';
            $wan_iface = $wan_interface ?? 'UNKNOWN_WAN';

            if ($interface === 'br0' || $interface === 'lo' || $interface === $wan_iface) {
                echo json_encode(['status' => 'error', 'message' => "Cannot {$action} '{$interface}' from the bridge. It's a critical system or WAN interface."]);
                exit();
            }

            $current_bridged_interfaces = get_bridge_interfaces($yq_path, $netplan_config_file);

            if ($action === 'add') {
                if (in_array($interface, $current_bridged_interfaces)) {
                    echo json_encode(['status' => 'error', 'message' => "Interface '{$interface}' is already in the bridge."]);
                    exit();
                }
                if (add_interface_to_bridge($yq_path, $netplan_config_file, $interface)) {
                    echo json_encode(apply_netplan($netplan_backup_file, $netplan_config_file, $netplan_cmd_path, $tee_cmd_path));
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Failed to add interface to bridge. Check logs.']);
                }
            } elseif ($action === 'remove') {
                if (!in_array($interface, $current_bridged_interfaces)) {
                    echo json_encode(['status' => 'error', 'message' => "Interface '{$interface}' is not currently in the bridge."]);
                    exit();
                }
                if (remove_interface_from_bridge($yq_path, $netplan_config_file, $interface)) {
                    echo json_encode(apply_netplan($netplan_backup_file, $netplan_config_file, $netplan_cmd_path, $tee_cmd_path));
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Failed to remove interface from bridge. Check logs.']);
                }
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
