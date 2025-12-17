<?php
require 'config.php';
header('Content-Type: application/json');
$key = "ztccc_secret_key";

// --- YARDIMCI FONKSİYONLAR ---
function logAct($u, $act, $st) { try { getDB()->insert("access_logs", ["username"=>$u, "action"=>$act, "status"=>$st, "ip_address"=>$_SERVER['REMOTE_ADDR']]); } catch(e){} }
function sign($d){ global $key; $d['ip']=$_SERVER['REMOTE_ADDR']; return base64_encode(json_encode($d)).'.'.hash_hmac('sha256',base64_encode(json_encode($d)),$key); }
function verify($t){ global $key; @list($p,$s)=explode('.',$t); if(hash_hmac('sha256',$p,$key)!==$s)return false; $d=json_decode(base64_decode($p),true); if($d['ip']!==$_SERVER['REMOTE_ADDR'])return false; return $d; }

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

// 2. SİSTEMLERİ GETİR
if ($act === 'get_systems') {
    $db = getDB();
    $data = $db->select("infrastructure", "*");
    echo json_encode(['status'=>'success', 'data'=>$data]);
    exit;
}

// 3. SİSTEMİ AÇ/KAPA (TOGGLE)
if ($act === 'toggle') {
    $id = $in['id'];
    $db = getDB();
    $sys = $db->get("infrastructure", "*", ["id" => $id]);
    $newState = ($sys['status'] === 'ON') ? 'OFF' : 'ON';

    // --- ZERO TRUST YETKİ MATRİSİ ---
    $allowed = false;
    // Düşük riskli sistemleri herkes yönetebilir
    if ($sys['sensitivity'] === 'LOW') $allowed = true;
    // Yüksek riskli sistemleri Mühendis ve Admin yönetebilir
    elseif ($sys['sensitivity'] === 'HIGH' && ($role === 'engineer' || $role === 'admin')) $allowed = true;
    // Kritik sistemleri SADECE Admin yönetebilir
    elseif ($sys['sensitivity'] === 'CRITICAL' && $role === 'admin') $allowed = true;

    if ($allowed) {
        $db->update("infrastructure", ["status" => $newState], ["id" => $id]);
        logAct($user, "SWITCH_{$sys['system_name']}", 'AUTHORIZED');
        echo json_encode(['status'=>'success']);
    } else {
        logAct($user, "ATTACK_{$sys['system_name']}", 'BLOCKED');
        http_response_code(403);
        echo json_encode(['status'=>'error', 'message'=>'YETKİSİZ ERİŞİM! Bu işlem engellendi.']);
    }
    exit;
}
?>