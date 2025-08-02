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
      <p><strong>Note:</strong> To modify which interfaces are part of the bridge, edit the Netplan YAML (e.g., <code>/etc/netplan/01-netcfg.yaml</code>) and run <code>sudo netplan apply</code> via SSH.</p>
    </div>

    <h2>Network Interface Overview</h2>
    <div class="card">
      <div id="interface_overview_message" class="message" style="display:none;"></div>
      <div id="interface_overview_error" class="error" style="display:none;"></div>

      <table class="interfaces-table">
        <thead>
          <tr>
            <th>Interface Name</th>
            <th>Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="interfaces_table_body">
          <tr>
            <td colspan="3" style="text-align: center; color: #888;">Loading interfaces...</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', async () => {
      const interfacesTableBody = document.getElementById('interfaces_table_body');
      const interfaceOverviewMessage = document.getElementById('interface_overview_message');
      const interfaceOverviewError = document.getElementById('interface_overview_error');

      function showFeedback(element, text) {
        element.textContent = text;
        element.style.display = 'block';
      }
      function hideFeedbacks() {
        interfaceOverviewMessage.style.display = 'none';
        interfaceOverviewError.style.display = 'none';
      }

      // Restore normalizeInterfaces function
      function normalizeInterfaces(orig) {
        const results = [];

        function splitNames(nameStr) {
          return nameStr
            .replace(/\r/g, ' ')
            .replace(/\n/g, ' ')
            .trim()
            .split(/\s+/)
            .filter(n => n.length > 0);
        }

        if (Array.isArray(orig)) {
          orig.forEach(item => {
            if (typeof item === 'string') {
              splitNames(item).forEach(n => results.push({ name: n }));
            } else if (item && typeof item === 'object') {
              // Ensure boolean values for flags, and handle potential concatenated names
              const base = {
                is_wan: !!item.is_wan,
                is_bridged: !!item.is_bridged,
                is_system: !!item.is_system,
                label: item.label || item.name || '' // Ensure label exists
              };
              if (typeof item.name === 'string' && (item.name.includes('\n') || /\s+/.test(item.name.trim()))) {
                splitNames(item.name).forEach(n => {
                  results.push({ ...base, name: n, label: n + (base.label.includes('WAN') ? ' (WAN)' : '') + (base.label.includes('Bridged') ? ' (Bridged)' : '') + (base.label.includes('System') ? ' (System)' : '') });
                });
              } else if (typeof item.name === 'string') {
                results.push({ ...base, name: item.name });
              } else {
                // Fallback for non-string names
                results.push({ ...base, name: String(item.name) });
              }
            } else {
              results.push({ name: String(item) });
            }
          });
          return results;
        }

        if (typeof orig === 'string') {
          splitNames(orig).forEach(n => results.push({ name: n }));
          return results;
        }

        return [];
      }

      async function fetchAndPopulateInterfaces() {
        hideFeedbacks();
        interfacesTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #888;">Loading interfaces...</td></tr>';

        try {
          const response = await fetch('update_netplan.php?action=get_interfaces');
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }
          const data = await response.json();

          if (data.status === 'success') {
            const interfaces = normalizeInterfaces(data.interfaces); // Apply normalization here
            interfacesTableBody.innerHTML = ''; // Clear loading message

            if (!Array.isArray(interfaces) || interfaces.length === 0) {
              interfacesTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #888;">No network interfaces detected.</td></tr>';
            } else {
              interfaces.forEach(iface => {
                const row = document.createElement('tr'); // Create new row for each interface

                const nameCell = document.createElement('td');
                const typeCell = document.createElement('td');
                const statusCell = document.createElement('td');
                
                // Determine typeText and statusText based on normalized data
                let typeText = 'Unknown';
                let statusText = 'N/A';

                if (iface.is_system) {
                    typeText = 'System (Loopback/Bridge)';
                    statusText = 'Active';
                } else if (iface.is_wan) {
                    typeText = 'WAN (Internet)';
                    statusText = 'Active';
                } else if (iface.is_bridged) {
                    typeText = 'LAN (Bridged)';
                    statusText = 'Active';
                } else {
                    typeText = 'LAN (Unassigned)';
                    statusText = 'Inactive';
                }

                // Populate cells
                nameCell.innerHTML = `<i class="fas fa-network-wired" style="margin-right:8px;"></i> ${iface.name || '—'}`;
                typeCell.textContent = typeText;
                statusCell.textContent = statusText;

                // Append cells to the row
                row.appendChild(nameCell);
                row.appendChild(typeCell);
                row.appendChild(statusCell);
                
                // Append the row to the table body
                interfacesTableBody.appendChild(row);
              });
            }
          } else {
            showFeedback(interfaceOverviewError, `Failed to load interfaces: ${data.message || 'unknown error'}`);
            interfacesTableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: #d9363e;">Error: ${data.message || 'unknown'}</td></tr>`;
          }
        } catch (err) {
          console.error('Network error fetching interfaces:', err);
          showFeedback(interfaceOverviewError, 'Network error or server unavailable when fetching interfaces.');
          interfacesTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #d9363e;">Network Error</td></tr>';
        }
      }

      fetchAndPopulateInterfaces();
    });
  </script>
</body>
</html>
