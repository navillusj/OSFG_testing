<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPTables Rules</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Current IPTables Rules</h1>
		<p><a href="index.php" class="button">Back to main page</a></p>
        <div class="info-note">
            <p>This page displays the active <code>iptables</code> rules. Any changes must be made via SSH or a dedicated firewall management tool (see below).</p>
            <p><strong>Note:</strong> Displaying rules requires specific sudo permissions for the web server user.</p>
        </div>

        <h2>IPv4 Rules (`iptables -L -v -n`)</h2>
        <div class="status-section">
            <pre><?php
                // Attempt to execute iptables command with sudo
                $output = shell_exec('sudo /usr/sbin/iptables -L -v -n');
                if (empty($output)) {
                    echo "Error: Could not retrieve IPv4 iptables rules.\n";
                    echo "Please ensure 'www-data' user has NOPASSWD sudo access for '/usr/sbin/iptables'.\n";
                    echo "Example: 'www-data ALL=NOPASSWD: /usr/sbin/iptables' in /etc/sudoers (use visudo).\n";
                } else {
                    echo htmlspecialchars($output);
                }
            ?></pre>
        </div>

        <h2>IPv4 Rules (iptables-save format)</h2>
        <div class="status-section">
            <pre><?php
                // Attempt to execute iptables-save command with sudo
                $output = shell_exec('sudo /usr/sbin/iptables-save');
                if (empty($output)) {
                    echo "Error: Could not retrieve IPv4 iptables-save rules.\n";
                    echo "Please ensure 'www-data' user has NOPASSWD sudo access for '/usr/sbin/iptables-save'.\n";
                    echo "Example: 'www-data ALL=NOPASSWD: /usr/sbin/iptables-save' in /etc/sudoers (use visudo).\n";
                } else {
                    echo htmlspecialchars($output);
                }
            ?></pre>
        </div>

        <h2>IPv6 Rules (`ip6tables -L -v -n`)</h2>
        <div class="status-section">
            <pre><?php
                // Attempt to execute ip6tables command with sudo
                $output = shell_exec('sudo /usr/sbin/ip6tables -L -v -n');
                if (empty($output)) {
                    echo "Error: Could not retrieve IPv6 ip6tables rules.\n";
                    echo "Please ensure 'www-data' user has NOPASSWD sudo access for '/usr/sbin/ip6tables'.\n";
                    echo "Example: 'www-data ALL=NOPASSWD: /usr/sbin/ip6tables' in /etc/sudoers (use visudo).\n";
                } else {
                    echo htmlspecialchars($output);
                }
            ?></pre>
        </div>

        <h2>IPv6 Rules (ip6tables-save format)</h2>
        <div class="status-section">
            <pre><?php
                // Attempt to execute ip6tables-save command with sudo
                $output = shell_exec('sudo /usr/sbin/ip6tables-save');
                if (empty($output)) {
                    echo "Error: Could not retrieve IPv6 ip6tables-save rules.\n";
                    echo "Please ensure 'www-data' user has NOPASSWD sudo access for '/usr/sbin/ip6tables-save'.\n";
                    echo "Example: 'www-data ALL=NOPASSWD: /usr/sbin/ip6tables-save' in /etc/sudoers (use visudo).\n";
                } else {
                    echo htmlspecialchars($output);
                }
            ?></pre>
        </div>

    </div>
    <footer>
        <p>&copy; <?php echo date("Y"); ?> Router Monitor | Last Updated: <?php echo date("Y-m-d H:i:s AEST"); ?></p>
    </footer>
</body>
</html>
