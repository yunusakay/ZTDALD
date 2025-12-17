<?php
require 'config.php';

ini_set('display_errors', 1);
error_reporting(E_ALL);

try {
    $dbFile = __DIR__ . '/ld.sqlite';
    
    if (file_exists($dbFile)) {
        unlink($dbFile);
    }

    $db = getDB();

    $db->query("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT, 
        password TEXT, 
        role TEXT,
        score INTEGER
    )");

    $db->insert("users", [
        ["username" => "analyst", "password" => "pass123", "role" => "viewer", "score" => 4500],
        ["username" => "manager", "password" => "pass123", "role" => "viewer", "score" => 12500],
        ["username" => "ceo",     "password" => "admin123","role" => "admin",  "score" => 45000]
    ]);

    echo "LD Sistemi Hazır. <a href='index.php'>Giriş Ekranına Git</a>";

} catch (Exception $e) {
    echo "Hata: " . $e->getMessage();
}
?>