<?php
// api.php - Backend Servisi
require_once 'config.php';

header('Content-Type: application/json');
// CORS (Farklı portlardan erişim için - Opsiyonel ama iyi bir pratiktir)
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

$action = $_GET['action'] ?? '';

// --- 1. GİRİŞ (LOGIN) ---
if ($action === 'login') {
    // Postman'den veya Axios'tan gelen JSON verisini al
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'] ?? '';
    $password = $input['password'] ?? '';

    $db = getDB();
    $user = $db->get("users", "*", ["username" => $username]);

    if ($user && password_verify($password, $user['password'])) {
        echo json_encode([
            'status' => 'success',
            'token' => createToken(['sub' => $username, 'role' => $user['role'], 'exp' => time() + TOKEN_EXPIRY]),
            'role' => $user['role']
        ]);
    } else {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Hatalı bilgiler.']);
    }
    exit;
}

// --- 2. TOKEN DOĞRULAMA (Middleware) ---
$headers = getallheaders();
$auth = $headers['Authorization'] ?? '';

if (!preg_match('/Bearer\s+(.*)/i', $auth, $matches)) {
    http_response_code(401); 
    echo json_encode(['status' => 'error', 'message' => 'Token yok.']); 
    exit;
}

$payload = verifyToken($matches[1]);
if (!$payload) {
    http_response_code(401); 
    echo json_encode(['status' => 'error', 'message' => 'Geçersiz Token.']); 
    exit;
}

// --- 3. YETKİ KONTROLÜ ---
$required = $access_policies[$action] ?? [];
if (empty($required) || !in_array($payload['role'], $required)) {
    http_response_code(403); 
    echo json_encode(['status' => 'error', 'message' => 'Yetkiniz yok.']); 
    exit;
}

// --- 4. SONUÇ ---
$msgs = [
    'view' => "Veriler başarıyla çekildi (View).",
    'edit' => "Kayıt düzenlendi (Edit).",
    'admin' => "Admin paneli açıldı.",
];
echo json_encode(['status' => 'success', 'data' => $msgs[$action]]);
?>