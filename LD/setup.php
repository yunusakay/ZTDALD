<?php
// setup.php - Hata Ayıklama Modlu Kurulum
require 'config.php';

// Hataları Ekrana Bas
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

try {
    echo "<h3>🛠️ Kurulum Başlıyor...</h3>";

    // 1. Veritabanı Bağlantısı
    $db = getDB();
    echo "✅ Veritabanı dosyasına bağlandı: " . __DIR__ . "/ld.sqlite<br>";

    // 2. Tabloyu Temizle
    $db->query("DROP TABLE IF EXISTS users");
    echo "✅ Eski tablolar silindi.<br>";

    // 3. Tabloyu Oluştur
    $db->query("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT, 
        password TEXT, 
        role TEXT
    )");
    echo "✅ 'users' tablosu oluşturuldu.<br>";

    // 4. Kullanıcıları Ekle
    $data = [
        ["username" => "analyst", "password" => "pass123", "role" => "viewer"],
        ["username" => "admin",   "password" => "pass456", "role" => "editor"]
    ];

    $db->insert("users", $data);
    
    // Ekleme İşlemini Kontrol Et
    $count = $db->count("users");
    if ($count > 0) {
        echo "✅ Kullanıcılar eklendi! Toplam Kayıt: $count<br>";
        echo "<hr><h3>🎉 KURULUM BAŞARILI!</h3>";
        echo "<a href='index.php' style='font-size:20px; font-weight:bold;'>👉 Giriş Yapmak İçin Tıkla</a>";
    } else {
        echo "❌ HATA: Kullanıcılar eklenemedi!<br>";
        print_r($db->error());
    }

} catch (Exception $e) {
    echo "❌ KRİTİK HATA: " . $e->getMessage();
}
?>