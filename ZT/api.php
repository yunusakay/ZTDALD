<?php
require 'config.php';
header('Content-Type: application/json');
$key = "vault_jwt_key";

// --- YARDIMCILAR ---
function logAct($u, $act, $st) { try { getDB()->insert("access_logs", ["username"=>$u, "action"=>$act, "status"=>$st, "ip_address"=>$_SERVER['REMOTE_ADDR']]); } catch(e){} }
function sign($d){ global $key; $d['ip']=$_SERVER['REMOTE_ADDR']; return base64_encode(json_encode($d)).'.'.hash_hmac('sha256',base64_encode(json_encode($d)),$key); }
function verify($t){ global $key; @list($p,$s)=explode('.',$t); if(hash_hmac('sha256',$p,$key)!==$s)return false; $d=json_decode(base64_decode($p),true); if($d['ip']!==$_SERVER['REMOTE_ADDR'])return false; return $d; }
function encryptDB($data) { return openssl_encrypt($data, 'AES-128-ECB', 'gizli_db_anahtari'); }
function decryptDB($data) { return openssl_decrypt($data, 'AES-128-ECB', 'gizli_db_anahtari'); }

$in = json_decode(file_get_contents('php://input'), true);
$act = $_GET['action'] ?? '';

// 1. GİRİŞ
if ($act === 'login') {
    $db = getDB();
    $u = $db->get("users", "*", ["username" => $in['username']]);
    if ($u && $u['password'] === $in['password']) {
        logAct($u['username'], 'LOGIN', 'SUCCESS');
        echo json_encode(['status'=>'success', 'token'=>sign(['sub'=>$u['username'], 'role'=>$u['role']]), 'role'=>$u['role']]);
    } else {
        logAct($in['username'], 'LOGIN', 'FAILED');
        echo json_encode(['status'=>'error']);
    }
    exit;
}

// TOKEN KONTROL
$headers = getallheaders();
$token = str_replace('Bearer ', '', $headers['Authorization'] ?? '');
$claims = verify($token);
if (!$claims) { http_response_code(401); echo json_encode(['status'=>'error']); exit; }
$user = $claims['sub']; $role = $claims['role'];

// 2. LİSTELEME
if ($act === 'get_vault') {
    $db = getDB();
    if ($role === 'intern') {
        $data = $db->select("vault", "*", ["sensitivity" => "LOW"]);
    } elseif ($role === 'tech') {
        $data = $db->select("vault", "*", ["sensitivity" => ["LOW", "HIGH"]]);
    } else {
        $data = $db->select("vault", "*");
    }
    foreach($data as &$row) { $row['real_password'] = ''; $row['revealed'] = false; }
    echo json_encode(['status'=>'success', 'data'=>$data]);
    exit;
}

// 3. ŞİFRE GÖSTER
if ($act === 'reveal') {
    $db = getDB();
    $item = $db->get("vault", "*", ["id" => $in['id']]);
    $allowed = false;
    if ($item['sensitivity'] === 'LOW') $allowed = true;
    elseif ($item['sensitivity'] === 'HIGH' && ($role === 'tech' || $role === 'admin')) $allowed = true;
    elseif ($item['sensitivity'] === 'CRITICAL' && $role === 'admin') $allowed = true;

    if ($allowed) {
        logAct($user, "REVEAL_{$item['service_name']}", 'AUTHORIZED');
        echo json_encode(['status'=>'success', 'password'=>decryptDB($item['encrypted_pass'])]);
    } else {
        logAct($user, "REVEAL_{$item['service_name']}", 'BLOCKED');
        http_response_code(403);
        echo json_encode(['status'=>'error', 'message'=>'Yetkisiz Erişim!']);
    }
    exit;
}

// 4. EKLEME (Create)
if ($act === 'add') {
    if ($role === 'intern' && $in['sensitivity'] !== 'LOW') {
        logAct($user, 'ADD_DATA', 'BLOCKED');
        http_response_code(403); echo json_encode(['status'=>'error', 'message'=>'Stajyer kritik veri ekleyemez!']); exit;
    }
    $db = getDB();
    $db->insert("vault", [
        "service_name" => $in['service'],
        "username_login" => $in['login'],
        "encrypted_pass" => encryptDB($in['pass']),
        "sensitivity" => $in['sensitivity'],
        "decided_by" => $in['decided_by']
    ]);
    logAct($user, 'ADD_DATA', 'SUCCESS');
    echo json_encode(['status'=>'success']);
    exit;
}

// 5. GÜNCELLEME (Update) - YENİ!
if ($act === 'update') {
    $db = getDB();
    $id = $in['id'];
    $item = $db->get("vault", "*", ["id" => $id]);

    // Zero Trust Kuralı: Stajyer düzenleme yapamaz. Sadece Admin ve Tech.
    if ($role === 'intern') {
        logAct($user, "EDIT_{$item['service_name']}", 'BLOCKED');
        http_response_code(403); 
        echo json_encode(['status'=>'error', 'message'=>'Stajyerlerin düzenleme yetkisi yoktur!']); 
        exit;
    }

    // Tech kullanıcıları CRITICAL veriyi düzenleyemez
    if ($role === 'tech' && $item['sensitivity'] === 'CRITICAL') {
        logAct($user, "EDIT_{$item['service_name']}", 'BLOCKED');
        http_response_code(403); 
        echo json_encode(['status'=>'error', 'message'=>'Sadece Admin kritik verileri düzenleyebilir!']); 
        exit;
    }

    // Güncelleme verisi
    $updateData = [
        "service_name" => $in['service'],
        "username_login" => $in['login'],
        "sensitivity" => $in['sensitivity'],
        "decided_by" => $in['decided_by']
    ];

    // Eğer şifre alanı boş değilse şifreyi de güncelle
    if (!empty($in['pass'])) {
        $updateData["encrypted_pass"] = encryptDB($in['pass']);
    }

    $db->update("vault", $updateData, ["id" => $id]);
    logAct($user, "EDIT_{$item['service_name']}", 'SUCCESS');
    echo json_encode(['status'=>'success']);
    exit;
}

// 6. SİLME (Delete)
if ($act === 'delete') {
    $db = getDB();
    $item = $db->get("vault", "*", ["id" => $in['id']]);
    $canDelete = false;
    
    if ($role === 'admin') $canDelete = true;
    elseif ($role === 'tech' && $item['sensitivity'] !== 'CRITICAL') $canDelete = true;

    if ($canDelete) {
        $db->delete("vault", ["id" => $in['id']]);
        logAct($user, "DELETE_{$item['service_name']}", 'SUCCESS');
        echo json_encode(['status'=>'success']);
    } else {
        logAct($user, "DELETE_{$item['service_name']}", 'BLOCKED');
        http_response_code(403); echo json_encode(['status'=>'error', 'message'=>'Silme yetkiniz yok!']);
    }
    exit;
}
?>