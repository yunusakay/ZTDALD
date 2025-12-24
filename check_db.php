<?php
require 'config.php';

header('Content-Type: text/plain');

echo "=== ZT Database Structure ===\n\n";

echo "ZT Users table:\n";
$users = $pdo->query("DESCRIBE zt_users")->fetchAll(PDO::FETCH_ASSOC);
foreach ($users as $col) {
    echo "- " . $col['Field'] . " (" . $col['Type'] . ")\n";
}

echo "\nZT Vault table:\n";
$vault = $pdo->query("DESCRIBE zt_vault")->fetchAll(PDO::FETCH_ASSOC);
foreach ($vault as $col) {
    echo "- " . $col['Field'] . " (" . $col['Type'] . ")\n";
}

echo "\n=== Sample Data ===\n\n";

echo "Sample ZT Users:\n";
$sample_users = $pdo->query("SELECT id, username, password FROM zt_users LIMIT 3")->fetchAll(PDO::FETCH_ASSOC);
foreach ($sample_users as $user) {
    echo "ID: " . $user['id'] . ", User: " . $user['username'] . ", Pass: " . substr($user['password'], 0, 20) . "...\n";
}

echo "\nSample ZT Vault:\n";
$sample_vault = $pdo->query("SELECT id, service, username, password FROM zt_vault LIMIT 3")->fetchAll(PDO::FETCH_ASSOC);
foreach ($sample_vault as $vault) {
    echo "ID: " . $vault['id'] . ", Service: " . $vault['service'] . ", Pass: " . substr($vault['password'], 0, 20) . "...\n";
}
?>
