<?php
require 'config.php';

header('Content-Type: text/plain');

echo "=== Login Debug ===\n\n";

// Test L users table
echo "L Users table structure:\n";
$users = $pdo->query("DESCRIBE l_users")->fetchAll(PDO::FETCH_ASSOC);
foreach ($users as $col) {
    echo "- " . $col['Field'] . " (" . $col['Type'] . ")\n";
}

echo "\nSample L Users:\n";
$sample_users = $pdo->query("SELECT id, username, password, role FROM l_users LIMIT 3")->fetchAll(PDO::FETCH_ASSOC);
foreach ($sample_users as $user) {
    echo "ID: " . $user['id'] . ", User: " . $user['username'] . ", Pass: " . $user['password'] . ", Role: " . $user['role'] . "\n";
}

echo "\n=== Test Login Query ===\n";

// Test the exact login query
$test_user = 'admin'; // Change this to a known username
$test_pass = 'admin'; // Change this to the correct password

echo "Testing login with user: $test_user, pass: $test_pass\n";

$stmt = $pdo->prepare("SELECT * FROM l_users WHERE username = ? AND password = ?");
$stmt->execute([$test_user, $test_pass]);
$user = $stmt->fetch();

if ($user) {
    echo "LOGIN SUCCESS!\n";
    echo "Found user: " . $user['username'] . ", Role: " . $user['role'] . "\n";
} else {
    echo "LOGIN FAILED!\n";
    
    // Try to find the user
    $stmt = $pdo->prepare("SELECT * FROM l_users WHERE username = ?");
    $stmt->execute([$test_user]);
    $user_check = $stmt->fetch();
    
    if ($user_check) {
        echo "User exists but password mismatch\n";
        echo "Stored password: " . $user_check['password'] . "\n";
        echo "Provided password: " . $test_pass . "\n";
    } else {
        echo "User not found\n";
    }
}
?>
