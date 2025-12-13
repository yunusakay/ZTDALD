<?php
// config.php - Merkezi Ayar Dosyası
require 'Medoo.php';
use Medoo\Medoo;

// Güvenlik Anahtarları
define('SECRET_KEY', 'cok_gizli_super_anahtar'); 
define('TOKEN_EXPIRY', 3600); // 1 saat

// Erişim Politikaları (Roller)
$access_policies = [
    'view' => ['viewer', 'editor'],
    'edit' => ['editor'],
    'admin' => ['admin_only'], // Admin kullanıcısı bile buraya giremez çünkü rolü 'editor'
];

// Veritabanı Bağlantısı (Fonksiyon)
function getDB() {
    return new Medoo([
        'type' => 'sqlite',
        'database' => 'database.sqlite'
    ]);
}

// --- Token İşlemleri (Saf PHP) ---

function createToken($payload) {
    $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $body   = base64_encode(json_encode($payload));
    $sig    = hash_hmac('sha256', "$header.$body", SECRET_KEY);
    return "$header.$body.$sig";
}

function verifyToken($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    
    list($h, $b, $s) = $parts;
    $check = hash_hmac('sha256', "$h.$b", SECRET_KEY);
    
    if (!hash_equals($s, $check)) return null;
    
    $payload = json_decode(base64_decode($b), true);
    if ($payload['exp'] < time()) return null;
    
    return $payload;
}
?>