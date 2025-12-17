<?php
require 'Medoo.php';
use Medoo\Medoo;
// ZT Güvenli Veritabanı
function getDB() {
    return new Medoo([
        'type' => 'sqlite',
        'database' => __DIR__ . '/zt_vault.sqlite' // İsim değişti
    ]);
}
?>