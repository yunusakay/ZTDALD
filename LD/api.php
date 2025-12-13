<?php
require 'config.php';

header('Content-Type: application/json');
$input = json_decode(file_get_contents('php://input'), true);
$action = $_GET['action'] ?? '';

if ($action === 'login') {
    $u = $input['username'] ?? '';
    $p = $input['password'] ?? '';
    
    $db = getDB();
    $user = $db->get("users", "*", ["username" => $u]);

    if ($user && $user['password'] === $p) {
        $_SESSION['uid'] = $user['id'];
        echo json_encode(['status' => 'success']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Fail']);
    }
    exit;
}

if ($action === 'logout') {
    session_destroy();
    echo json_encode(['status' => 'success']);
    exit;
}

if (!isset($_SESSION['uid'])) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Auth Required']);
    exit;
}
if ($action === 'admin_data') {
    $db = getDB();
    $data = $db->select("users", "*");
    echo json_encode(['status' => 'success', 'data' => $data]);
} else {
    echo json_encode(['status' => 'success', 'data' => 'Standard Data']);
}
?>