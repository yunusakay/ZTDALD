<?php
require 'config.php';

try {
    $dbFile = __DIR__ . '/l_vault.sqlite';
    if (file_exists($dbFile)) unlink($dbFile);
    $db = getDB();

    $db->query("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)");
    // Şifreli değil, Düz Metin (text) tutuyoruz
    $db->query("CREATE TABLE vault (id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT, username_login TEXT, encrypted_pass TEXT, sensitivity TEXT, decided_by TEXT)");
    
    // Kullanıcılar
    $db->insert("users", [
        ["username" => "stajyer", "password" => "123", "role" => "intern"],
        ["username" => "uzman",   "password" => "123", "role" => "tech"],
        ["username" => "ceo",     "password" => "123", "role" => "admin"]
    ]);

    // Veriler (Şifreleme fonksiyonu kullanmıyoruz, direkt yazıyoruz)
    $data = [
        ["Ofis Misafir Wi-Fi", "guest_wifi", "Misafir2024!", "LOW", "Resepsiyon"],
        ["Instagram Hesabı", "sirket_resmi", "SocialGuru#99", "LOW", "Pazarlama Md."],
        ["Slack Bot Token", "dev_bot", "xoxb-98765-TOKEN", "LOW", "Takım Lideri"],
        ["Jira Admin Paneli", "admin@sirket.com", "ProjectM@ster", "HIGH", "CTO"],
        ["Linux Prod Sunucu", "root", "X9#mK_SuperRoot", "HIGH", "SysAdmin"],
        ["VPN Genel Giriş", "vpn_user", "SecureTunnel_v2", "HIGH", "Network Md."],
        ["AWS Ana API Key", "aws_admin", "AKIA_CRITICAL_KEY", "CRITICAL", "CEO"],
        ["Kurumsal Banka", "finans_mudur", "9876-BANK-CODE", "CRITICAL", "CFO"],
        ["Veritabanı Master", "postgres", "Db_Sup3r_P4ss", "CRITICAL", "Güvenlik Ekibi"]
    ];

    foreach ($data as $d) {
        $db->insert("vault", [
            "service_name" => $d[0],
            "username_login" => $d[1],
            "encrypted_pass" => $d[2], // ŞİFRELEME YOK! (Plaintext)
            "sensitivity" => $d[3],
            "decided_by" => $d[4]
        ]);
    }
    echo "Legacy (Güvensiz) Kurulum Tamamlandı.";
} catch (Exception $e) { echo $e->getMessage(); }
?>