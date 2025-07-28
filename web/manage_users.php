<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit();
}

$users_file = '/var/www/html/users.json';
$message = '';
$error = '';

function loadUsers() {
    global $users_file, $error;
    if (!file_exists($users_file)) {
        error_log("Error: users.json not found at $users_file. Cannot load users.");
        $error = "User database not found. Please re-run the installation script.";
        return ['users' => []];
    }
    $json_content = file_get_contents($users_file);
    if ($json_content === false) {
        error_log("Error: Failed to read users.json at $users_file. Check permissions.");
        $error = "Failed to read user data. Check file permissions.";
        return ['users' => []];
    }
    $data = json_decode($json_content, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("Error: Invalid JSON format in users.json: " . json_last_error_msg());
        $error = "User database corrupted. Invalid JSON format.";
        return ['users' => []];
    }
    return $data;
}

function saveUsers($data) {
    global $users_file, $error;
    $json_content = json_encode($data, JSON_PRETTY_PRINT);
    if (file_put_contents($users_file, $json_content) === false) {
        error_log("Error: Failed to write to users.json at $users_file. Check permissions.");
        $error = "Failed to save user data. Check file permissions.";
        return false;
    }
    return true;
}

$current_user = $_SESSION['username'];
$users_data = loadUsers();
$users = $users_data['users'];

// Add new user
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_user') {
    $new_username = trim($_POST['new_username']);
    $new_password = $_POST['new_password'];
    
    if (empty($new_username) || empty($new_password)) {
        $error = "Username and password cannot be empty.";
    } elseif (in_array($new_username, array_column($users, 'username'))) {
        $error = "Username already exists.";
    } else {
        $password_hash = hash('sha256', $new_password);
        $users[] = ['username' => $new_username, 'password_hash' => $password_hash];
        $users_data['users'] = $users;
        if (saveUsers($users_data)) {
            $message = "User '{$new_username}' added successfully.";
        }
    }
}

// Remove user
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'remove_user') {
    $remove_username = $_POST['remove_username'];
    $new_users = [];
    $removed = false;
    foreach ($users as $user) {
        if ($user['username'] !== $remove_username) {
            $new_users[] = $user;
        } else {
            $removed = true;
        }
    }
    if (!$removed) {
        $error = "User '{$remove_username}' not found.";
    } elseif (count($new_users) === 0) {
        $error = "Cannot remove the last user. At least one user must exist.";
    } else {
        $users_data['users'] = $new_users;
        if (saveUsers($users_data)) {
            $users = $new_users; // Update the local user list
            $message = "User '{$remove_username}' removed successfully.";
        }
    }
}

// Update password
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_password') {
    $update_username = $_POST['update_username'];
    $new_password = $_POST['new_password'];
    
    if (empty($new_password)) {
        $error = "Password cannot be empty.";
    } else {
        $updated = false;
        foreach ($users as &$user) {
            if ($user['username'] === $update_username) {
                $user['password_hash'] = hash('sha256', $new_password);
                $updated = true;
                break;
            }
        }
        if ($updated && saveUsers($users_data)) {
            $message = "Password for user '{$update_username}' updated successfully.";
        } elseif (!$updated) {
            $error = "User '{$update_username}' not found.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body>
    <div class="container">
        <h1>User Management</h1>
        <a href="settings.php" class="button"><i class="fas fa-arrow-left"></i> Back to Settings</a>

        <?php if ($message): ?>
            <div class="message"><?php echo $message; ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <h2>Add New User</h2>
        <div class="card">
            <form action="manage_users.php" method="post">
                <input type="hidden" name="action" value="add_user">
                <label for="new_username">Username:</label>
                <input type="text" id="new_username" name="new_username" required>
                <label for="new_password">Password:</label>
                <input type="password" id="new_password" name="new_password" required>
                <div class="form-actions">
                    <button type="submit" class="button"><i class="fas fa-plus"></i> Add User</button>
                </div>
            </form>
        </div>

        <h2>Current Users</h2>
        <div class="grid">
            <?php foreach ($users as $user): ?>
            <div class="card">
                <h3><i class="fas fa-user-circle"></i> <?php echo htmlspecialchars($user['username']); ?></h3>
                <?php if ($user['username'] !== $current_user): ?>
                <form action="manage_users.php" method="post" onsubmit="return confirm('Are you sure you want to remove user \'<?php echo htmlspecialchars($user['username']); ?>\'?');">
                    <input type="hidden" name="action" value="remove_user">
                    <input type="hidden" name="remove_username" value="<?php echo htmlspecialchars($user['username']); ?>">
                    <button type="submit" class="button" style="background-color: #d9363e;"><i class="fas fa-trash-alt"></i> Remove User</button>
                </form>
                <?php endif; ?>
                <form action="manage_users.php" method="post" style="margin-top: 15px;">
                    <input type="hidden" name="action" value="update_password">
                    <input type="hidden" name="update_username" value="<?php echo htmlspecialchars($user['username']); ?>">
                    <label for="update_password_<?php echo htmlspecialchars($user['username']); ?>">New Password:</label>
                    <input type="password" id="update_password_<?php echo htmlspecialchars($user['username']); ?>" name="new_password" required>
                    <div class="form-actions">
                        <button type="submit" class="button sync-button"><i class="fas fa-key"></i> Update Password</button>
                    </div>
                </form>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</body>
</html>
