<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

// Helper for executing commands safely
function secure_shell_exec($command, $log_context = 'general') {
    error_log(sprintf("[%s] Executing command for %s: %s", date('Y-m-d H:i:s'), $log_context, $command));
    $output = shell_exec($command . ' 2>&1');
    if ($output === null) {
        error_log(sprintf("[%s] ERROR: Command failed for %s. Command: '%s'", date('Y-m-d-H:i:s'), $log_context, $command));
        return "Error: Command failed or not found.";
    }
    return trim($output);
}

$message = '';
$error = '';
$hostapd_conf_path = '/etc/hostapd/hostapd.conf';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_wifi'])) {
    $ssid = isset($_POST['ssid']) ? trim($_POST['ssid']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    if ($ssid === '' || $password === '') {
        $error = "SSID and Password cannot be empty.";
    } else {
        $escaped_ssid = escapeshellarg($ssid);
        $escaped_password = escapeshellarg($password);
        // Replace with your actual update mechanism/script
        $command = "sudo /usr/local/bin/update_hostapd.sh {$escaped_ssid} {$escaped_password}";
        $output = secure_shell_exec($command, 'wifi_update');

        if (str_starts_with($output, 'Error:')) {
            $error = "Failed to update Wi-Fi settings. " . htmlspecialchars($output);
        } else {
            $message = "Wi-Fi settings updated successfully.";
        }
    }
}

// Read current hostapd configuration to show existing SSID/password (masking recommended)
$current_ssid = 'N/A';
$current_pass = 'N/A';
if (file_exists($hostapd_conf_path)) {
    $conf_content = file_get_contents($hostapd_conf_path);
    if ($conf_content !== false) {
        if (preg_match('/^ssid=(.*)$/m', $conf_content, $m)) {
            $current_ssid = trim($m[1]);
        }
        if (preg_match('/^wpa_passphrase=(.*)$/m', $conf_content, $m)) {
            $current_pass = trim($m[1]);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Router Settings</title>
  <link rel="stylesheet" href="style.css"/>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"/>
  <style>
    /* Additions for toggle switch */
    .switch {
        position: relative;
        display: inline-block;
        width: 40px; /* Smaller switch */
        height: 24px;
    }
    .switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }
    .slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #d9363e; /* Red for off/down/not member */
        transition: .4s;
        border-radius: 24px; /* Half of height for rounded corners */
    }
    .slider:before {
        position: absolute;
        content: "";
        height: 16px; /* Smaller circle */
        width: 16px;
        left: 4px;
        bottom: 4px;
        background-color: white;
        transition: .4s;
        border-radius: 50%;
    }
    input:checked + .slider {
        background-color: #50c878; /* Green for on/up/is member */
    }
    input:checked + .slider:before {
        transform: translateX(16px); /* Move 16px (width) for 40px switch */
    }
    .status-text {
        font-weight: bold;
        margin-left: 8px; /* Space between toggle and text */
        vertical-align: middle;
    }
    .status-up { color: #50c878; }
    .status-down { color: #d9363e; }
    /* End toggle switch additions */

    body { background: #0f1118; font-family: system-ui,-apple-system,BlinkMacSystemFont,sans-serif; color: #e5e9f0; margin: 0; padding: 0; }
    .container { max-width: 1000px; margin: 0 auto; padding: 24px; }
    .button { padding: 8px 14px; text-decoration: none; background: #2563eb; color: #fff; border-radius: 6px; margin-right: 8px; display: inline-block; font-size: 0.9rem; }
    .card { background: #1f242d; padding: 18px; border-radius: 10px; margin-bottom: 24px; }
    .message { background: #1e4620; padding: 10px; border-radius: 4px; margin: 8px 0; }
    .error { background: #5f1f1f; padding: 10px; border-radius: 4px; margin: 8px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { padding: 12px 14px; text-align: left; }
    thead { background: #0f1118; }
    tr { border-bottom: 1px solid #2a2e3b; }
    .note { background: #1f2330; padding: 12px; border-radius: 6px; margin-bottom: 16px; }
    input[type=text], input[type=password] { width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #333; background: #0f1118; color: #fff; margin-top:4px; }
    .form-actions { margin-top: 12px; }
    h1, h2 { margin: 0 0 12px 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Router Settings</h1>
    <div style="margin-bottom:16px;">
      <a href="index.php" class="button"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
      <a href="manage_users.php" class="button"><i class="fas fa-users"></i> Manage Users</a>
    </div>

    <?php if ($message): ?>
      <div class="message"><?php echo htmlspecialchars($message); ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
      <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <h2>Wi-Fi Access Point Settings</h2>
    <div class="card">
      <p>Current SSID: <strong><?php echo htmlspecialchars($current_ssid); ?></strong></p>
      <p>Current Password: <strong><?php echo htmlspecialchars($current_pass); ?></strong> (consider hiding this in production).</p>
      <form action="settings.php" method="post" style="margin-top: 16px;">
        <input type="hidden" name="update_wifi" value="1" />
        <div>
          <label for="ssid">New SSID:</label><br/>
          <input type="text" id="ssid" name="ssid" value="<?php echo htmlspecialchars($current_ssid); ?>" required />
        </div>
        <div style="margin-top:10px;">
          <label for="password">New Password:</label><br/>
          <input type="password" id="password" name="password" placeholder="Enter new password" required />
        </div>
        <div class="form-actions">
          <button type="submit" class="button"><i class="fas fa-save"></i> Update Wi-Fi Settings</button>
        </div>
      </form>
    </div>

    <div class="note">
      <p><strong>Note:</strong> Interfaces added/removed from the bridge will persist across reboots via Netplan configuration. Disabling an interface via its toggle is a temporary state change.</p>
    </div>

    <h2>Network Interface Overview</h2>
    <div class="card">
      <div id="interface_overview_message" class="message" style="display:none;"></div>
      <div id="interface_overview_error" class="error" style="display:none;"></div>
      
      <div style="margin-bottom: 15px;">
        <button id="refresh_now_btn" class="button"><i class="fas fa-sync-alt"></i> Refresh Now</button>
        <button id="toggle_auto_refresh_btn" class="button"><i class="fas fa-pause"></i> Pause Auto-Refresh</button>
        <span id="refresh_status" style="margin-left: 10px; color: #aaa;">Auto-refresh: Active (30s)</span>
      </div>

      <table class="interfaces-table">
        <thead>
          <tr>
            <th>Interface Name</th>
            <th>Type</th>
            <th>Operational State</th>
            <th>Bridge Member</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="interfaces_table_body">
          <tr>
            <td colspan="5" style="text-align: center; color: #888;">Loading interfaces...</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let trafficSnapshots = {};
    let autoRefreshInterval = null;
    const REFRESH_INTERVAL_SECS = 30;
    const TRAFFIC_SAMPLING_DELAY_MS = 1500;

    document.addEventListener('DOMContentLoaded', async () => {
      const interfacesTableBody = document.getElementById('interfaces_table_body');
      const interfaceOverviewMessage = document.getElementById('interface_overview_message');
      const interfaceOverviewError = document.getElementById('interface_overview_error');
      const refreshNowBtn = document.getElementById('refresh_now_btn');
      const toggleAutoRefreshBtn = document.getElementById('toggle_auto_refresh_btn');
      const refreshStatusSpan = document.getElementById('refresh_status');

      function showFeedback(element, text, type) {
        element.textContent = text;
        element.className = type;
        element.style.display = 'block';
      }
      function hideFeedbacks() {
        interfaceOverviewMessage.style.display = 'none';
        interfaceOverviewError.style.display = 'none';
      }

      function normalizeInterfaces(dataInterfaces) {
          if (!Array.isArray(dataInterfaces)) {
              const names = String(dataInterfaces || '').trim().split(/\s+/).filter(n => n.length > 0);
              return names.map(name => ({
                  name: name,
                  type_label: 'Unknown',
                  oper_state: 'UNKNOWN',
                  rx_bytes: 0,
                  tx_bytes: 0,
                  is_wan: false,
                  is_bridged: false,
                  is_system: false
              }));
          }

          return dataInterfaces.map(iface => ({
              name: iface.name || '—',
              type_label: iface.type_label || 'Unknown',
              oper_state: (typeof iface.oper_state === 'string' ? iface.oper_state.toUpperCase() : 'UNKNOWN'), 
              rx_bytes: parseInt(iface.rx_bytes) || 0,
              tx_bytes: parseInt(iface.tx_bytes) || 0,
              is_wan: !!iface.is_wan,
              is_bridged: !!iface.is_bridged,
              is_system: !!iface.is_system
          }));
      }

      async function fetchAndPopulateInterfaces() {
        hideFeedbacks();
        interfacesTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888;">Loading interfaces...</td></tr>';

        try {
          // First fetch for current state and initial traffic snapshot
          const response1 = await fetch('update_netplan.php?action=get_interfaces');
          if (!response1.ok) throw new Error(`HTTP ${response1.status}`);
          const data1 = await response1.json();
          if (data1.status !== 'success') throw new Error(`Backend error: ${data1.message}`);

          const interfaces1 = normalizeInterfaces(data1.interfaces);
          const now1 = new Date().getTime();
          interfaces1.forEach(iface => {
              trafficSnapshots[iface.name] = { rx: iface.rx_bytes, tx: iface.tx_bytes, timestamp: now1 };
          });

          // Wait a short period, then fetch again for traffic comparison
          await new Promise(resolve => setTimeout(resolve, TRAFFIC_SAMPLING_DELAY_MS));

          const response2 = await fetch('update_netplan.php?action=get_interfaces');
          if (!response2.ok) throw new Error(`HTTP ${response2.status}`);
          const data2 = await response2.json();
          if (data2.status !== 'success') throw new Error(`Backend error: ${data2.message}`);
          
          const interfaces = normalizeInterfaces(data2.interfaces); // This is the data to display

          interfacesTableBody.innerHTML = ''; // Clear loading message

          if (interfaces.length === 0) {
            interfacesTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888;">No network interfaces detected.</td></tr>';
          } else {
            interfaces.forEach(iface => {
              const row = document.createElement('tr');

              const nameCell = document.createElement('td');
              const typeCell = document.createElement('td');
              const operStateCell = document.createElement('td');
              const bridgeMemberCell = document.createElement('td');
              const actionCell = document.createElement('td');
              
              // Determine Operational State
              const isOperUp = iface.oper_state === 'UP';
              const operStateText = isOperUp ? 'Active' : iface.oper_state;
              const operStateClass = isOperUp ? 'status-up' : 'status-down';

              nameCell.innerHTML = `<i class="fas fa-network-wired" style="margin-right:8px;"></i> ${iface.name}`;
              typeCell.textContent = iface.type_label;
              operStateCell.innerHTML = `<span class="${operStateClass}">${operStateText}</span>`;
              
              // Bridge Member Toggle
              const isCriticalForBridge = iface.is_wan || iface.is_system;
              const bridgeToggleChecked = iface.is_bridged ? 'checked' : '';
              const bridgeToggleDisabled = isCriticalForBridge ? 'disabled' : '';

              bridgeMemberCell.innerHTML = `
                  <label class="switch">
                      <input type="checkbox" data-interface="${iface.name}" data-action-type="bridge" ${bridgeToggleChecked} ${bridgeToggleDisabled}>
                      <span class="slider round"></span>
                  </label>
              `;

              // Operational State Toggle (Action Column)
              const isCriticalForOperState = iface.is_wan || iface.is_system;
              const operStateToggleChecked = isOperUp ? 'checked' : '';
              const operStateToggleDisabled = isCriticalForOperState ? 'disabled' : '';

              actionCell.innerHTML = `
                  <label class="switch">
                      <input type="checkbox" data-interface="${iface.name}" data-action-type="operstate" ${operStateToggleChecked} ${operStateToggleDisabled}>
                      <span class="slider round"></span>
                  </label>
              `;
              
              row.appendChild(nameCell);
              row.appendChild(typeCell);
              row.appendChild(operStateCell);
              row.appendChild(bridgeMemberCell);
              row.appendChild(actionCell);
              
              interfacesTableBody.appendChild(row);
            });
            
            // Add event listeners for all toggles
            // Remove existing listeners to prevent duplicates on refresh
            document.querySelectorAll('.interfaces-table input[type="checkbox"]').forEach(oldToggle => {
                oldToggle.removeEventListener('change', handleToggleChange);
            });
            document.querySelectorAll('.interfaces-table input[type="checkbox"]').forEach(newToggle => {
                newToggle.addEventListener('change', handleToggleChange);
            });
          }
        } catch (err) {
          console.error('Network error or backend issue fetching interfaces:', err);
          showFeedback(interfaceOverviewError, `Error fetching interfaces: ${err.message}`, 'error');
          interfacesTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #d9363e;">Error: ${err.message}</td></tr>`;
        }
      }
      
      // Centralized event handler for toggles
      async function handleToggleChange(event) {
          const interfaceName = event.target.dataset.interface;
          const actionType = event.target.dataset.actionType;
          let successMessage = '';
          let errorMessage = '';
          let apiAction = '';
          let postBody = '';

          if (actionType === 'operstate') {
            const newState = event.target.checked ? 'up' : 'down';
            if (!confirm(`Are you sure you want to set interface '${interfaceName}' to '${newState.toUpperCase()}'? This may disrupt network connectivity.`)) {
                event.target.checked = !event.target.checked;
                return;
            }
            apiAction = 'set_interface_state';
            postBody = `interface=${encodeURIComponent(interfaceName)}&state=${encodeURIComponent(newState)}`;
            successMessage = `Interface '${interfaceName}' set to '${newState.toUpperCase()}' successfully.`;
            errorMessage = `Failed to set interface '${interfaceName}' to '${newState.toUpperCase()}'.`;
          } else if (actionType === 'bridge') {
            const newMembership = event.target.checked ? 'add' : 'remove';
            if (!confirm(`Are you sure you want to ${newMembership} interface '${interfaceName}' ${newMembership === 'add' ? 'to' : 'from'} the bridge (br0)? This will apply Netplan changes and may briefly disrupt network connectivity.`)) {
                event.target.checked = !event.target.checked;
                return;
            }
            apiAction = 'set_bridge_membership';
            postBody = `interface=${encodeURIComponent(interfaceName)}&action_type=${encodeURIComponent(newMembership)}`;
            successMessage = `Interface '${interfaceName}' ${newMembership === 'add' ? 'added to' : 'removed from'} bridge successfully.`;
            errorMessage = `Failed to ${newMembership} interface '${interfaceName}' ${newMembership === 'add' ? 'to' : 'from'} bridge.`;
          } else {
              return; // Unknown action type
          }

          try {
            showFeedback(interfaceOverviewMessage, `Processing ${interfaceName}...`, 'message');
            hideFeedbacks();

            const response = await fetch(`update_netplan.php?action=${apiAction}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: postBody
            });
            const data = await response.json();

            if (data.status === 'success') {
              showFeedback(interfaceOverviewMessage, data.message || successMessage, 'message');
              await fetchAndPopulateInterfaces(); // Re-fetch after successful action
            } else {
              showFeedback(interfaceOverviewError, data.message || errorMessage, 'error');
              event.target.checked = !event.target.checked;
            }
          } catch (error) {
            console.error('Error in interface action:', error);
            showFeedback(interfaceOverviewError, 'Network error or server unavailable when performing action.', 'error');
            event.target.checked = !event.target.checked;
          }
      }

      // --- Auto-refresh controls ---
      function startAutoRefresh() {
          if (autoRefreshInterval) clearInterval(autoRefreshInterval);
          autoRefreshInterval = setInterval(() => fetchAndPopulateInterfaces(), REFRESH_INTERVAL_SECS * 1000);
          toggleAutoRefreshBtn.innerHTML = '<i class="fas fa-pause"></i> Pause Auto-Refresh';
          refreshStatusSpan.textContent = `Auto-refresh: Active (${REFRESH_INTERVAL_SECS}s)`;
          toggleAutoRefreshBtn.classList.remove('paused');
      }

      function stopAutoRefresh() {
          if (autoRefreshInterval) clearInterval(autoRefreshInterval);
          autoRefreshInterval = null;
          toggleAutoRefreshBtn.innerHTML = '<i class="fas fa-play"></i> Resume Auto-Refresh';
          refreshStatusSpan.textContent = 'Auto-refresh: Paused';
          toggleAutoRefreshBtn.classList.add('paused');
      }

      refreshNowBtn.addEventListener('click', () => {
          stopAutoRefresh();
          fetchAndPopulateInterfaces(); // Immediate refresh
          setTimeout(startAutoRefresh, 5000); // Resume auto-refresh after 5 seconds
      });

      toggleAutoRefreshBtn.addEventListener('click', () => {
          if (autoRefreshInterval) {
              stopAutoRefresh();
          } else {
              startAutoRefresh();
          }
      });

      startAutoRefresh(); // Start auto-refresh on page load
    });
  </script>
</body>
</html>
