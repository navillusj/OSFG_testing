<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Function to safely execute shell commands (though not directly used by the new Netplan UI)
function secure_shell_exec($command, $log_context = 'general') {
    error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $command));
    $output = shell_exec($command . ' 2>&1');
    if ($output === null) {
        error_log(sprintf("[%s] ERROR: Command failed for %s. Command: '%s'", date('Y-m-d H:i:s'), $log_context, $command));
        return "Error: Command failed or not found.";
    }
    return trim($output);
}

// Global variables for messages (initialize empty)
$message = '';
$error = '';

// --- Handle Wi-Fi settings form submission ---
$hostapd_conf_path = '/etc/hostapd/hostapd.conf'; // Define path here

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_wifi'])) {
    if (isset($_POST['ssid']) && isset($_POST['password'])) {
        $ssid = trim($_POST['ssid']);
        $password = trim($_($_POST['password']));

        if (empty($ssid) || empty($password)) {
            $error = "SSID and Password cannot be empty.";
        } else {
            $command = "sudo /usr/local/bin/update_hostapd.sh " . escapeshellarg($ssid) . " " . escapeshellarg($password) . " 2>&1";
            $output = shell_exec($command);
            
            if (strpos($output, 'Error:') === false) {
                $message = "Wi-Fi settings updated successfully. Service restarted.";
            } else {
                $error = "Failed to update Wi-Fi settings. " . htmlspecialchars($output);
            }
        }
    }
}

// Read current Wi-Fi settings to pre-populate the form
$current_ssid = 'N/A';
$current_pass = 'N/A';
if (file_exists($hostapd_conf_path)) {
    $conf_content = file_get_contents($hostapd_conf_path);
    if ($conf_content !== false) {
        if (preg_match('/^ssid=(.*)$/m', $conf_content, $matches)) {
            $current_ssid = $matches[1];
        }
        // NOTE: Reading plaintext password from config file is a security risk.
        // It's displayed here for convenience but in a production system,
        // it should probably just show '********' or require re-entry.
        if (preg_match('/^wpa_passphrase=(.*)$/m', $conf_content, $matches)) {
            $current_pass = $matches[1];
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Settings</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body>
    <div class="container">
        <h1>Router Settings</h1>
        <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
        <a href="manage_users.php" class="button"><i class="fas fa-users"></i> Manage Users</a>
        
        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <h2>Wi-Fi Access Point Settings</h2>
        <div class="card">
            <p>Current SSID: <strong><?php echo htmlspecialchars($current_ssid); ?></strong></p>
            <p>Current Password: <strong><?php echo htmlspecialchars($current_pass); ?></strong> (for security, consider not displaying actual password)</p>
            <form action="settings.php" method="post" style="margin-top: 20px;">
                <input type="hidden" name="update_wifi" value="1">
                <label for="ssid">New SSID:</label>
                <input type="text" id="ssid" name="ssid" value="<?php echo htmlspecialchars($current_ssid); ?>" required>
                <label for="password">New Password:</label>
                <input type="password" id="password" name="password" placeholder="Enter new password" required>
                <div class="form-actions">
                    <button type="submit" class="button"><i class="fas fa-save"></i> Update Wi-Fi Settings</button>
                </div>
            </form>
        </div>
        
        <div class="note">
            <p><strong>Note:</strong> Network Interface Management is now handled via the "Bridge Interface Management" section for improved usability and error reduction.</p>
        </div>

        <h2>Bridge Interface Management (br0)</h2>
        <div class="card">
            <div class="note">
                <p><strong>Warning:</strong> Incorrectly modifying bridge interfaces can lead to loss of network connectivity.</p>
                <p>Interfaces added to the bridge will be configured without DHCP (<code>dhcp4: no</code>) in Netplan.</p>
                <p>Removing an interface from the bridge will also remove its direct Netplan configuration.</p>
                <p>WAN (Internet-facing) interfaces cannot be added to or removed from the bridge here.</p>
            </div>
            
            <div id="netplan_message" class="message" style="display:none; margin-top:15px;"></div>
            <div id="netplan_error" class="error" style="display:none; margin-top:15px;"></div>

            <h3>Manage Bridge Members</h3>
            <div class="form-group" style="margin-bottom: 20px;">
                <label for="all_interfaces_select">Select Interface:</label>
                <select id="all_interfaces_select" style="width: 100%; padding: 10px; background-color: #2a2a2a; border: 1px solid #444; border-radius: 6px; color: #e0e0e0;">
                    <option value="">Loading interfaces...</option>
                </select>
                <div class="form-actions" style="margin-top: 15px;">
                    <button type="button" id="add_to_bridge_btn" class="button button-add" disabled><i class="fas fa-plus"></i> Add to br0</button>
                    <button type="button" id="remove_from_bridge_btn" class="button button-remove" disabled><i class="fas fa-minus"></i> Remove from br0</button>
                </div>
            </div>

            <h3>Interfaces Currently in br0</h3>
            <ul id="bridged_interfaces_list" style="list-style-type: none; padding: 0;">
                <li style="color: #888;">Loading...</li>
            </ul>
        </div>
        </div>

    <script>
        document.addEventListener('DOMContentLoaded', async () => {
            const allInterfacesSelect = document.getElementById('all_interfaces_select');
            const bridgedInterfacesList = document.getElementById('bridged_interfaces_list');
            const addToBridgeBtn = document.getElementById('add_to_bridge_btn');
            const removeFromBridgeBtn = document.getElementById('remove_from_bridge_btn');
            const netplanMessage = document.getElementById('netplan_message');
            const netplanError = document.getElementById('netplan_error');

            let allInterfacesData = []; // To store the full interface data including bridged/wan status

            function showFeedback(element, text, type) {
                element.textContent = text;
                element.className = type; // 'message' or 'error'
                element.style.display = 'block';
            }

            function hideFeedback() {
                netplanMessage.style.display = 'none';
                netplanError.style.display = 'none';
            }

            async function fetchAndPopulateInterfaces() {
                hideFeedback();
                allInterfacesSelect.innerHTML = '<option value="">Loading interfaces...</option>';
                bridgedInterfacesList.innerHTML = '<li style="color: #888;">Loading...</li>';
                
                // Disable buttons while loading
                addToBridgeBtn.disabled = true;
                removeFromBridgeBtn.disabled = true;

                try {
                    const response = await fetch('update_netplan.php?action=get_interfaces');
                    const data = await response.json();

                    if (data.status === 'success') {
                        allInterfacesData = data.interfaces; // Store the data
                        
                        // Populate combined interfaces dropdown
                        allInterfacesSelect.innerHTML = '';
                        if (allInterfacesData.length === 0) {
                            allInterfacesSelect.innerHTML = '<option value="">No interfaces detected</option>';
                        } else {
                            allInterfacesData.forEach(iface => {
                                const option = document.createElement('option');
                                option.value = iface.name;
                                option.textContent = iface.label; // Correctly sets text for each option
                                allInterfacesSelect.appendChild(option);
                            });
                        }

                        // Enable/disable buttons based on initial selection or data availability
                        if (allInterfacesData.length > 0 && allInterfacesSelect.value) {
                            addToBridgeBtn.disabled = false;
                            removeFromBridgeBtn.disabled = false;
                        } else {
                            addToBridgeBtn.disabled = true;
                            removeFromBridgeBtn.disabled = true;
                        }

                        // Populate interfaces currently in bridge list
                        bridgedInterfacesList.innerHTML = '';
                        if (data.in_bridge.length === 0) {
                            bridgedInterfacesList.innerHTML = '<li style="color: #888;">No interfaces currently in br0.</li>';
                        } else {
                            data.in_bridge.forEach(iface => {
                                const listItem = document.createElement('li');
                                listItem.style.marginBottom = '10px';
                                listItem.innerHTML = `
                                    <i class="fas fa-link" style="color: #4a90e2; margin-right: 8px;"></i>
                                    ${iface}
                                `;
                                bridgedInterfacesList.appendChild(listItem);
                            });
                        }
                    } else {
                        showFeedback(netplanError, `Failed to load interfaces: ${data.message}`, 'error');
                        allInterfacesSelect.innerHTML = '<option value="">Error loading interfaces</option>';
                        allInterfacesSelect.disabled = true;
                        addToBridgeBtn.disabled = true;
                        removeFromBridgeBtn.disabled = true;
                        bridgedInterfacesList.innerHTML = `<li class="error" style="color: #d9363e;">Error: ${data.message}</li>`;
                    }
                } catch (error) {
                    console.error('Network error fetching interfaces:', error);
                    showFeedback(netplanError, 'Network error or server unavailable when fetching interfaces.', 'error');
                    allInterfacesSelect.innerHTML = '<option value="">Network Error</option>';
                    allInterfacesSelect.disabled = true;
                    addToBridgeBtn.disabled = true;
                    removeFromBridgeBtn.disabled = true;
                    bridgedInterfacesList.innerHTML = `<li class="error" style="color: #d9363e;">Network Error</li>`;
                }
            }

            // Initial load of interfaces
            fetchAndPopulateInterfaces();

            // Handle Add to Bridge button click
            addToBridgeBtn.addEventListener('click', async () => {
                hideFeedback();
                const selectedInterfaceName = allInterfacesSelect.value;
                if (!selectedInterfaceName) {
                    showFeedback(netplanError, 'Please select an interface.', 'error');
                    return;
                }

                // Get the full data for the selected interface
                const selectedInterface = allInterfacesData.find(iface => iface.name === selectedInterfaceName);

                if (selectedInterface.is_wan || selectedInterface.name === 'br0' || selectedInterface.name === 'lo') {
                    showFeedback(netplanError, `'${selectedInterface.label}' cannot be added to the bridge.`, 'error');
                    return;
                }
                if (selectedInterface.is_bridged) {
                     showFeedback(netplanError, `'${selectedInterface.label}' is already in the bridge.`, 'error');
                     return;
                }

                if (!confirm(`Are you sure you want to add '${selectedInterface.label}' to the bridge (br0) and apply Netplan changes? This may briefly disrupt network connectivity.`)) {
                    return;
                }

                try {
                    const response = await fetch('update_netplan.php?action=add_to_bridge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `interface=${encodeURIComponent(selectedInterfaceName)}`
                    });
                    const data = await response.json();
                    if (data.status === 'success') {
                        showFeedback(netplanMessage, data.message, 'message');
                        await fetchAndPopulateInterfaces(); // Refresh the lists
                    } else {
                        showFeedback(netplanError, `Failed to add interface: ${data.message}`, 'error');
                    }
                } catch (error) {
                    console.error('Error adding interface to bridge:', error);
                    showFeedback(netplanError, 'Network error or server unavailable when adding interface.', 'error');
                }
            });

            // Handle Remove from Bridge button click
            removeFromBridgeBtn.addEventListener('click', async () => {
                hideFeedback();
                const selectedInterfaceName = allInterfacesSelect.value;
                if (!selectedInterfaceName) {
                    showFeedback(netplanError, 'Please select an interface.', 'error');
                    return;
                }

                const selectedInterface = allInterfacesData.find(iface => iface.name === selectedInterfaceName);

                if (selectedInterface.is_wan || selectedInterface.name === 'br0' || selectedInterface.name === 'lo') {
                    showFeedback(netplanError, `'${selectedInterface.label}' cannot be removed from the bridge via this interface.`, 'error');
                    return;
                }
                if (!selectedInterface.is_bridged) {
                    showFeedback(netplanError, `'${selectedInterface.label}' is not currently in the bridge (br0).`, 'error');
                    return;
                }

                if (!confirm(`Are you sure you want to remove '${selectedInterface.label}' from the bridge (br0) and apply Netplan changes? This may briefly disrupt network connectivity.`)) {
                    return;
                }

                try {
                    const response = await fetch('update_netplan.php?action=remove_from_bridge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `interface=${encodeURIComponent(selectedInterfaceName)}`
                    });
                    const data = await response.json();
                    if (data.status === 'success') {
                        showFeedback(netplanMessage, data.message, 'message');
                        await fetchAndPopulateInterfaces(); // Refresh the lists
                    } else {
                        showFeedback(netplanError, `Failed to remove interface: ${data.message}`, 'error');
                    }
                } catch (error) {
                    console.error('Error removing interface from bridge:', error);
                    showFeedback(netplanError, 'Network error or server unavailable when removing interface.', 'error');
                }
            });
        });
    </script>
</body>
</html>
