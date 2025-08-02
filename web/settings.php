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
        background-color: #d9363e; /* Red for off/down */
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
        background-color: #50c878; /* Green for on/up */
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
      <p><strong>Note:</strong> To modify which interfaces are part of the bridge, edit the Netplan YAML (e.g., <code>/etc/netplan/01-network-config.yaml</code>) and run <code>sudo netplan apply</code> via SSH.</p>
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
            <th>Traffic Status</th>
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
    let trafficSnapshots = {}; // Stores { ifaceName: { rx: bytes, tx: bytes, timestamp: ms } } for comparison
    let autoRefreshInterval = null;
    const REFRESH_INTERVAL_SECS = 30;
    const TRAFFIC_SAMPLING_DELAY_MS = 1500; // Delay between initial and second fetch for traffic

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

      async function fetchAndPopulateInterfaces(fetchPhase = 1) { // Phase 1: initial data; Phase 2: traffic comparison
        if (fetchPhase === 1) {
            hideFeedbacks();
            interfacesTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888;">Loading interfaces...</td></tr>';
        }

        try {
          const response = await fetch('update_netplan.php?action=get_interfaces');
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }
          const data = await response.json();

          if (data.status === 'success') {
            const currentInterfaces = normalizeInterfaces(data.interfaces);
            const now = new Date().getTime();

            if (fetchPhase === 1) {
                // Store first snapshot for traffic comparison
                trafficSnapshots = {};
                currentInterfaces.forEach(iface => {
                    trafficSnapshots[iface.name] = { rx: iface.rx_bytes, tx: iface.tx_bytes, timestamp: now };
                });
                // Schedule the second fetch for traffic comparison
                setTimeout(() => fetchAndPopulateInterfaces(2), TRAFFIC_SAMPLING_DELAY_MS);
                return; // Exit this phase 1 call
            }

            // --- Phase 2: Populate table with calculated traffic status ---
            interfacesTableBody.innerHTML = ''; // Clear loading message

            if (currentInterfaces.length === 0) {
              interfacesTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888;">No network interfaces detected.</td></tr>';
            } else {
              currentInterfaces.forEach(iface => {
                const row = document.createElement('tr');

                const nameCell = document.createElement('td');
                const typeCell = document.createElement('td');
                const operStateCell = document.createElement('td');
                const trafficStatusCell = document.createElement('td');
                const actionCell = document.createElement('td');
                
                // Determine Operational State (direct from kernel 'oper_state')
                const isOperUp = iface.oper_state === 'UP'; // Strict check for 'UP'
                const operStateText = isOperUp ? 'Active' : iface.oper_state; // Display actual state if not UP
                const operStateClass = isOperUp ? 'status-up' : 'status-down';

                // Determine Traffic Status based on byte changes
                let isTrafficActive = false;
                const prevTraffic = trafficSnapshots[iface.name];
                if (prevTraffic) {
                    const rxChange = iface.rx_bytes - prevTraffic.rx;
                    const txChange = iface.tx_bytes - prevTraffic.tx;
                    // Consider active if any byte change. A small positive threshold (e.g., 100 bytes) can filter noise.
                    const TRAFFIC_THRESHOLD_BYTES = 100; // Small threshold to count as "traffic"
                    if (rxChange > TRAFFIC_THRESHOLD_BYTES || txChange > TRAFFIC_THRESHOLD_BYTES) {
                        isTrafficActive = true;
                    }
                }
                const trafficStatusText = isTrafficActive ? 'Transmitting' : 'No Traffic';
                const trafficStatusClass = isTrafficActive ? 'status-up' : 'status-down';

                nameCell.innerHTML = `<i class="fas fa-network-wired" style="margin-right:8px;"></i> ${iface.name}`;
                typeCell.textContent = iface.type_label;
                operStateCell.innerHTML = `<span class="${operStateClass}">${operStateText}</span>`;
                trafficStatusCell.innerHTML = `<span class="${trafficStatusClass}">${trafficStatusText}</span>`;

                // Create toggle switch
                const isCriticalInterface = iface.is_wan || iface.is_system;
                const toggleChecked = isOperUp ? 'checked' : ''; // Toggle state based on oper_state
                const toggleDisabled = isCriticalInterface ? 'disabled' : '';

                actionCell.innerHTML = `
                    <label class="switch">
                        <input type="checkbox" data-interface="${iface.name}" ${toggleChecked} ${toggleDisabled}>
                        <span class="slider round"></span>
                    </label>
                `;
                
                row.appendChild(nameCell);
                row.appendChild(typeCell);
                row.appendChild(operStateCell);
                row.appendChild(trafficStatusCell);
                row.appendChild(actionCell);
                
                interfacesTableBody.appendChild(row);
              });
              
              // Add event listeners for toggles (only once after table is built)
              // Ensure we don't re-add listeners on every refresh to prevent duplicates
              if (!interfacesTableBody.dataset.listenersAdded) {
                document.querySelectorAll('.interfaces-table input[type="checkbox"]').forEach(toggle => {
                  toggle.addEventListener('change', async (event) => {
                    const interfaceName = event.target.dataset.interface;
                    const newState = event.target.checked ? 'up' : 'down';

                    if (!confirm(`Are you sure you want to set interface '${interfaceName}' to '${newState.toUpperCase()}'? This may disrupt network connectivity.`)) {
                        event.target.checked = !event.target.checked;
                        return;
                    }

                    try {
                      showFeedback(interfaceOverviewMessage, `Setting ${interfaceName} to ${newState.toUpperCase()}...`, 'message');
                      hideFeedbacks();

                      const response = await fetch('update_netplan.php?action=set_interface_state', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `interface=${encodeURIComponent(interfaceName)}&state=${encodeURIComponent(newState)}`
                      });
                      const data = await response.json();

                      if (data.status === 'success') {
                        showFeedback(interfaceOverviewMessage, data.message, 'message');
                        // After state change, force a full refresh (Phase 1) to re-evaluate activity
                        await fetchAndPopulateInterfaces(1); 
                      } else {
                        showFeedback(interfaceOverviewError, data.message, 'error');
                        event.target.checked = !event.target.checked;
                      }
                    } catch (error) {
                      console.error('Error setting interface state:', error);
                      showFeedback(interfaceOverviewError, 'Network error or server unavailable when setting interface state.', 'error');
                      event.target.checked = !event.target.checked;
                    }
                  });
                });
                interfacesTableBody.dataset.listenersAdded = 'true'; // Mark listeners as added
              }
            }
          } else {
            showFeedback(interfaceOverviewError, `Failed to load interfaces: ${data.message || 'unknown error'}`, 'error');
            interfacesTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #d9363e;">Error: ${data.message || 'unknown'}</td></tr>`;
          }
        } catch (err) {
          console.error('Network error fetching interfaces:', err);
          showFeedback(interfaceOverviewError, 'Network error or server unavailable when fetching interfaces.', 'error');
          interfacesTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #d9363e;">Network Error</td></tr>';
        }
      }

      // --- Auto-refresh controls ---
      function startAutoRefresh() {
          if (autoRefreshInterval) clearInterval(autoRefreshInterval);
          autoRefreshInterval = setInterval(() => fetchAndPopulateInterfaces(1), REFRESH_INTERVAL_SECS * 1000); // Always start with Phase 1
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
          stopAutoRefresh(); // Pause auto-refresh on manual trigger
          fetchAndPopulateInterfaces(1); // Trigger immediate refresh (Phase 1)
          // Resume auto-refresh after a short delay to allow manual refresh cycle to complete
          setTimeout(startAutoRefresh, 5000); // Resume after 5 seconds
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
