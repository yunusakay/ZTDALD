<?php
require '../ZT/Medoo.php'; // Medoo'yu ZT klasöründen ödünç alabilir veya kopyalayabilirsiniz
use Medoo\Medoo;

// L Güvensiz Veritabanı
function getDB() {
    return new Medoo([
        'type' => 'sqlite',
        'database' => __DIR__ . '/l_vault.sqlite'
    ]);
}
?>