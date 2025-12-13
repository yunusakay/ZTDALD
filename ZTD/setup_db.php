<?php
// setup_db.php - Veritabanını Sıfırdan Kurar
require 'Medoo.php';
use Medoo\Medoo;

try {
    // SQLite dosyasını oluşturur
    $database = new Medoo([
        'type' => 'sqlite',
        'database' => 'database.sqlite'
    ]);

    // Tabloyu temizle ve oluştur
    $database->query("DROP TABLE IF EXISTS users");
    $database->query("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )");

    // Test kullanıcılarını ekle
    $database->insert("users", [
        [
            "username" => "analyst",
            "password" => password_hash('pass123', PASSWORD_DEFAULT),
            "role" => "viewer"
        ],
        [
            "username" => "admin",
            "password" => password_hash('pass456', PASSWORD_DEFAULT),
            "role" => "editor"
        ]
    ]);

    echo "<h3>✅ Veritabanı Hazır!</h3> 'database.sqlite' dosyası oluşturuldu.";

} catch (Exception $e) {
    echo "Hata: " . $e->getMessage();
}
?>