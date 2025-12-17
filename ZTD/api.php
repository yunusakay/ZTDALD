<?php
require 'config.php';
header('Content-Type: application/json');
$key = "vault_jwt_key";

// --- YARDIMCILAR ---
function logAct($u, $act, $st) { try { getDB()->insert("access_logs", ["username"=>$u, "action"=>$act, "status"=>$st, "ip_address"=>$_SERVER['REMOTE_ADDR']]); } catch(e){} }
function sign($d){ global $key; $d['ip']=$_SERVER['REMOTE_ADDR']; return base64_encode(json_encode($d)).'.'.hash_hmac('sha256',base64_encode(json_encode($d)),$key); }
function verify($t){ global $key; @list($p,$s)=explode('.',$t); if(hash_hmac('sha256',$p,$key)!==$s)return false; $d=json_decode(base64_decode($p),true); if($d['ip']!==$_SERVER['REMOTE_ADDR'])return false; return $d; }

// Veritabanındaki şifreyi çözme fonksiyonu (Sadece API yapabilir)
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
$claims = verify(str_replace('Bearer ', '', getallheaders()['Authorization'] ?? ''));
if (!$claims) { http_response_code(401); echo json_encode(['status'=>'error']); exit; }
$user = $claims['sub']; $role = $claims['role'];

// 2. KASA LİSTESİ (Şifreler GİZLİ Gider - Maskelenmiş)
if ($act === 'get_vault') {
    $db = getDB();
    // Listeyi çekerken şifreleri asla göndermiyoruz, sadece yıldız gönderiyoruz
    // Ancak Zero Trust gereği, Stajyer CRITICAL olanın varlığını bile görmemeli (Scoping)
    
    if ($role === 'intern') {
        $data = $db->select("vault", ["id","service_name","username_login","sensitivity","icon"], ["sensitivity" => "LOW"]);
    } elseif ($role === 'tech') {
        $data = $db->select("vault", ["id","service_name","username_login","sensitivity","icon"], ["sensitivity" => ["LOW", "HIGH"]]);
    } else {
        $data = $db->select("vault", ["id","service_name","username_login","sensitivity","icon"]); // Admin hepsi
    }
    
    // Şifre alanı boş veya maskeli gider
    foreach($data as &$row) { $row['password_display'] = '••••••••••••'; }
    
    echo json_encode(['status'=>'success', 'data'=>$data]);
    exit;
}

// 3. ŞİFREYİ GÖSTER (Reveal Password)
if ($act === 'reveal') {
    $id = $in['id'];
    $db = getDB();
    $item = $db->get("vault", "*", ["id" => $id]);

    // YETKİ KONTROLÜ
    $allowed = false;
    if ($item['sensitivity'] === 'LOW') $allowed = true;
    elseif ($item['sensitivity'] === 'HIGH' && ($role === 'tech' || $role === 'admin')) $allowed = true;
    elseif ($item['sensitivity'] === 'CRITICAL' && $role === 'admin') $allowed = true;

    if ($allowed) {
        // Veritabanındaki şifreli veriyi çöz
        $realPass = decryptDB($item['encrypted_pass']);
        
        logAct($user, "REVEAL_{$item['service_name']}", 'AUTHORIZED');
        echo json_encode(['status'=>'success', 'password'=>$realPass]);
    } else {
        logAct($user, "ATTACK_{$item['service_name']}", 'BLOCKED');
        http_response_code(403);
        echo json_encode(['status'=>'error', 'message'=>'BU ŞİFREYİ GÖRME YETKİNİZ YOK!']);
    }
    exit;
}
?>