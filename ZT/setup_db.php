<?php
require 'config.php';

function encryptDB($data) {
    return openssl_encrypt($data, 'AES-128-ECB', 'gizli_db_anahtari');
}

try {
    $dbFile = __DIR__ . '/ztd.sqlite';
    if (file_exists($dbFile)) unlink($dbFile);
    $db = getDB();

    $db->query("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)");
    $db->query("CREATE TABLE vault (id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT, username_login TEXT, encrypted_pass TEXT, sensitivity TEXT, icon TEXT)");
    $db->query("CREATE TABLE access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, status TEXT, ip_address TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");

    $db->insert("users", [
        ["username" => "stajyer", "password" => "123", "role" => "intern"],  // Sadece Wi-Fi görür
        ["username" => "devops",  "password" => "123", "role" => "tech"],    // Sunucuları görür
        ["username" => "ceo",     "password" => "123", "role" => "admin"]    // Her şeyi görür
    ]);

    // KASA İÇERİĞİ (Şifreler DB'de şifreli durur!)
    $db->insert("vault", [
        ["service_name" => "Ofis Misafir Wi-Fi", "username_login" => "guest_wifi", "encrypted_pass" => encryptDB("Misafir2024!"), "sensitivity" => "LOW", "icon" => "📶"],
        ["service_name" => "Instagram Hesabı",   "username_login" => "sirket_resmi", "encrypted_pass" => encryptDB("InstaMarketing99"), "sensitivity" => "LOW", "icon" => "📱"],
        ["service_name" => "Linux Prod Sunucu",  "username_login" => "root",         "encrypted_pass" => encryptDB("X9#mK_SuperRoot"),  "sensitivity" => "HIGH", "icon" => "🖥️"],
        ["service_name" => "AWS Ana API Key",    "username_login" => "aws_admin",    "encrypted_pass" => encryptDB("AKIA_CRITICAL_KEY"),"sensitivity" => "CRITICAL", "icon" => "☁️"],
        ["service_name" => "Kurumsal Banka",     "username_login" => "finans_mudur", "encrypted_pass" => encryptDB("9876-BANK-CODE"),   "sensitivity" => "CRITICAL", "icon" => "🏦"]
    ]);

    echo "<body style='background:#111; color:#0f0; font-family:sans-serif; text-align:center; padding-top:50px;'>";
    echo "<h1>🔐 ZT-VAULT KURULDU</h1>";
    echo "<p>Veriler AES ile şifrelendi. Veritabanı çalınsa bile okunamaz.</p>";
    echo "<a href='dashboard.php' style='color:#fff; border:1px solid #fff; padding:10px; text-decoration:none;'>KASAYA GİRİŞ YAP</a>";
    echo "</body>";

} catch (Exception $e) { echo $e->getMessage(); }
?>