<?php
session_start();

// Check for a login state, if already logged in, redirect to the dashboard
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header('Location: index.php');
    exit();
}

// Function to load users from the JSON file
function loadUsers() {
    $users_file = '/var/www/html/users.json';
    if (!file_exists($users_file)) {
        // Log error and create an empty users.json if it's missing.
        error_log("Error: users.json not found at $users_file. Creating empty file.");
        file_put_contents($users_file, '{"users": []}');
        return ['users' => []];
    }
    $json_content = file_get_contents($users_file);
    if ($json_content === false) {
        error_log("Error: Failed to read users.json at $users_file. Check permissions.");
        return ['users' => []];
    }
    $data = json_decode($json_content, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("Error: Invalid JSON format in users.json: " . json_last_error_msg());
        // Attempt to fix by writing empty array if JSON is bad.
        file_put_contents($users_file, '{"users": []}');
        return ['users' => []];
    }
    return $data;
}

$error = '';
$users_data = loadUsers();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $submitted_username = $_POST['username'];
        $submitted_password_hash = hash('sha256', $_POST['password']);
        
        $authenticated = false;
        if (isset($users_data['users']) && is_array($users_data['users'])) {
            foreach ($users_data['users'] as $user) {
                if (isset($user['username']) && isset($user['password_hash'])) {
                    if ($user['username'] === $submitted_username && $user['password_hash'] === $submitted_password_hash) {
                        $authenticated = true;
                        $_SESSION['username'] = $submitted_username; // Store username in session
                        break;
                    }
                }
            }
        }

        if ($authenticated) {
            $_SESSION['logged_in'] = true;
            header('Location: index.php');
            exit();
        } else {
            $error = 'Invalid username or password.';
        }
    }
}

// Function to safely execute shell commands
function secure_shell_exec($command) {
    $output = shell_exec($command . ' 2>&1');
    return trim($output);
}

// Get system information for the login page
$uptime = htmlspecialchars(secure_shell_exec('uptime -p'));
$datetime = date('Y-m-d H:i:s A');
$version = "1.0.0"; // Define your project version here
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Login</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body class="login-page">
    <div class="login-container">
        <img src="logo.png" alt="Logo" class="login-logo">
        <h1>Router Management</h1>

        <div class="system-info">
            <p><strong>Version:</strong> <?php echo $version; ?></p>
            <p><strong>Uptime:</strong> <?php echo $uptime; ?></p>
            <p><strong>Date & Time:</strong> <?php echo $datetime; ?></p>
        </div>

        <?php if (!empty($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form action="login.php" method="post" class="login-form">
            <div class="input-group">
                <i class="fas fa-user"></i>
                <input type="text" name="username" placeholder="Username" required>
            </div>
            <div class="input-group">
                <i class="fas fa-lock"></i>
                <input type="password" name="password" placeholder="Password" required>
            </div>
            <button type="submit" class="button">Login</button>
        </form>
    </div>
</body>
</html>
