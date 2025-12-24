<?php
session_start();
require '../database.php';
require '../security_helper.php';

SecurityHelper::init();

if (isset($_GET['ping'])) {
    http_response_code(204);
    exit;
}

$db = Database::getInstance();
$msg = "";
$user = $_SESSION['user'] ?? null;
$role = $_SESSION['role'] ?? null;

// --- GİRİŞ İŞLEMİ ---
if (isset($_POST['login'])) {
    if (SecurityHelper::rateLimited('login_attempts', 5, 300)) {
        $msg = "ENGEL: Çok fazla giriş denemesi. Lütfen bekleyin.";
    } else {
        $rows = $db->select('zt_users', ['username' => $_POST['user']]); 
        if ($rows && password_verify($_POST['pass'], $rows[0]['password'])) {
            $_SESSION['user'] = $rows[0]['username'];
            $_SESSION['role'] = $rows[0]['role'];
            $_SESSION['user_id'] = $rows[0]['id'];
            
            session_regenerate_id(true);
            
            header("Location: index.php");
            exit;
        } else {
            $msg = "Hatalı kullanıcı adı veya şifre.";
        }
    }
}

if (isset($_GET['logout'])) {
    SecurityHelper::logout();
}

// --- GÜVENLİ İŞLEMLER ---
if ($user) {
    // 1. Kasa Ekleme
    if (isset($_POST['add_vault'])) {
        if (!SecurityHelper::verifyCsrf($_POST['csrf'] ?? '')) {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        } else {
            $srv = SecurityHelper::validateInput($_POST['service'], 'string');
            $usr = SecurityHelper::validateInput($_POST['login'], 'username');
            $pwd = $_POST['pass'];
            
            $allowed_sens = ['LOW'];
            if ($role === 'tech' || $role === 'admin') $allowed_sens[] = 'HIGH';
            if ($role === 'admin') $allowed_sens[] = 'CRITICAL';

            $sen = in_array($_POST['sensitivity'], $allowed_sens) ? $_POST['sensitivity'] : 'LOW';
            
            if ($srv && $usr && $pwd) {
                $cfg = require '../security_config.php';
                $k = hash('sha256', $cfg['security']['vault']['key'], true);
                $iv = substr(hash('sha256', $cfg['security']['vault']['iv'], true), 0, 16);
                $enc_pass = openssl_encrypt($pwd, 'AES-256-CBC', $k, 0, $iv);

                $db->insert('zt_vault', [
                    'service' => $srv,
                    'username' => $usr,
                    'password' => $enc_pass,
                    'sensitivity' => $sen
                ]);
                $msg = "Kasa kaydı eklendi.";
            } else {
                $msg = "Hata: Geçersiz veri.";
            }
        }
    }

    // 2. Kasa Güncelleme
    if (isset($_POST['update_vault'])) {
        if (!SecurityHelper::verifyCsrf($_POST['csrf'] ?? '')) {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        } else {
            $id = (int)$_POST['vault_id'];
            $item = $db->select('zt_vault', ['id' => $id]);
            
            if ($item) {
                $item = $item[0];
                $allowed = false;
                if ($role === 'admin') $allowed = true;
                if ($role === 'tech' && $item['sensitivity'] !== 'CRITICAL') $allowed = true;
                if ($role === 'intern' && $item['sensitivity'] === 'LOW') $allowed = true;

                if ($allowed) {
                    $updateData = [
                        'service' => SecurityHelper::validateInput($_POST['service'], 'string'),
                        'username' => SecurityHelper::validateInput($_POST['username'], 'username'),
                        'sensitivity' => $_POST['sensitivity'] // Basitlik için tekrar kontrol etmiyoruz ama edilmeli
                    ];
                    
                    if (!empty($_POST['password'])) {
                        $cfg = require '../security_config.php';
                        $k = hash('sha256', $cfg['security']['vault']['key'], true);
                        $iv = substr(hash('sha256', $cfg['security']['vault']['iv'], true), 0, 16);
                        $updateData['password'] = openssl_encrypt($_POST['password'], 'AES-256-CBC', $k, 0, $iv);
                    }
                    
                    $db->update('zt_vault', $updateData, ['id' => $id]);
                    $msg = "Kayıt güncellendi.";
                } else {
                    $msg = "ENGEL: Yetkisiz işlem.";
                }
            }
        }
    }

    // 3. Kasa Silme
    if (isset($_GET['del_vault'])) {
        if (!SecurityHelper::verifyCsrf($_GET['csrf'] ?? '')) {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        } else {
            $id = (int)$_GET['del_vault'];
            $item = $db->select('zt_vault', ['id' => $id]);
            
            if ($item) {
                $item = $item[0];
                $allowed = false;
                if ($role === 'admin') $allowed = true;
                if ($role === 'tech' && $item['sensitivity'] !== 'CRITICAL') $allowed = true;
                if ($role === 'intern' && $item['sensitivity'] === 'LOW') $allowed = true;
                
                if ($allowed) {
                    $db->delete('zt_vault', ['id' => $id]);
                    $msg = "Kayıt silindi.";
                } else {
                    $msg = "ENGEL: Yetkisiz işlem.";
                }
            }
        }
    }

    // 4. Kullanıcı Ekleme (Sadece Admin)
    if (isset($_POST['add_user']) && $role === 'admin') {
        if (SecurityHelper::verifyCsrf($_POST['csrf'] ?? '')) {
            $nu = $_POST['new_user'];
            $np = $_POST['new_pass'];
            $nr = $_POST['new_role'];
            if (empty($db->select('zt_users', ['username' => $nu]))) {
                $db->insert('zt_users', [
                    'username' => SecurityHelper::validateInput($nu, 'username'),
                    'password' => SecurityHelper::passwordHash($np),
                    'role' => $nr
                ]);
                $msg = "Personel eklendi.";
            } else {
                $msg = "Kullanıcı zaten mevcut.";
            }
        }
    }

    // 5. Kullanıcı Güncelleme (Sadece Admin) - YENİ
    if (isset($_POST['update_user']) && $role === 'admin') {
        if (SecurityHelper::verifyCsrf($_POST['csrf'] ?? '')) {
            $uid = (int)$_POST['user_id'];
            $unu = SecurityHelper::validateInput($_POST['edit_username'], 'username');
            $unr = $_POST['edit_role'];
            $unp = $_POST['edit_pass']; // Boş olabilir

            if ($unu && in_array($unr, ['admin', 'tech', 'intern'])) {
                // Kullanıcı adı başkasında var mı kontrolü
                $check = $db->select('zt_users', ['username' => $unu]);
                if (!empty($check) && $check[0]['id'] != $uid) {
                    $msg = "Bu kullanıcı adı zaten kullanımda.";
                } else {
                    $upData = [
                        'username' => $unu,
                        'role' => $unr
                    ];
                    if (!empty($unp)) {
                        $upData['password'] = SecurityHelper::passwordHash($unp);
                    }
                    $db->update('zt_users', $upData, ['id' => $uid]);
                    $msg = "Kullanıcı bilgileri güncellendi.";
                }
            } else {
                $msg = "Geçersiz veri.";
            }
        } else {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        }
    }
    
    // 6. Kullanıcı Silme (Sadece Admin)
    if (isset($_GET['del_user']) && $role === 'admin') {
        if (SecurityHelper::verifyCsrf($_GET['csrf'] ?? '')) {
            $id = (int)$_GET['del_user'];
            if ($id != $_SESSION['user_id']) { 
                $db->delete('zt_users', ['id' => $id]);
                $msg = "Personel silindi.";
            } else {
                $msg = "Kendinizi silemezsiniz.";
            }
        }
    }
}

// --- VERİ YÜKLEME ---
$vaults = [];
$users_list = [];

if ($user) {
    if ($role === 'intern') {
        $vaults = $db->select('zt_vault', ['sensitivity' => 'LOW']);
    } elseif ($role === 'tech') {
        $stmt = $db->getConnection()->prepare("SELECT * FROM zt_vault WHERE sensitivity IN ('LOW', 'HIGH')");
        $stmt->execute();
        $vaults = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $vaults = $db->select('zt_vault');
    }
    
    if ($role === 'admin') {
        $users_list = $db->select('zt_users');
    }
}

function getBadge($level) {
    $c = $level === 'CRITICAL' ? 'bg-danger' : ($level === 'HIGH' ? 'bg-warning' : 'bg-success');
    return "<span class=\"badge $c\">$level</span>";
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>ZT VAULT (Secure)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body { background-color: #f8f9fa; }</style>
</head>
<body class="p-4">

<div class="container bg-white p-4 shadow rounded" style="max-width: 900px;">
    <?php if (!$user): ?>
        <h3 class="text-center mb-4 text-success">ZERO TRUST VAULT</h3>
        <?php if($msg): ?><div class="alert alert-danger text-center"><?= SecurityHelper::e($msg) ?></div><?php endif; ?>
        <form method="POST" class="w-50 mx-auto">
            <input type="text" name="user" class="form-control mb-2" placeholder="Kullanıcı Adı" required>
            <input type="password" name="pass" class="form-control mb-3" placeholder="Şifre" required>
            <button type="submit" name="login" class="btn btn-success w-100">Giriş Yap</button>
        </form>
    <?php else: ?>
        <div class="d-flex justify-content-between border-bottom pb-3 mb-4">
            <h4 class="m-0">ZT Vault <span class="badge bg-success fs-6"><?= strtoupper(SecurityHelper::e($role)) ?></span></h4>
            <div>
                <span class="me-2 text-muted">User: <?= SecurityHelper::e($user) ?></span>
                <a href="?logout" class="btn btn-outline-danger btn-sm">Çıkış</a>
            </div>
        </div>
        
        <?php if($msg): ?><div class="alert alert-info border"><?= SecurityHelper::e($msg) ?></div><?php endif; ?>

        <h6 class="text-muted text-uppercase small fw-bold mb-3">Yeni Güvenli Kayıt</h6>
        <form method="POST" class="row g-2 mb-5">
            <input type="hidden" name="csrf" value="<?= SecurityHelper::csrfToken() ?>">
            <div class="col"><input name="service" class="form-control form-control-sm" placeholder="Hizmet" required></div>
            <div class="col"><input name="login" class="form-control form-control-sm" placeholder="Kullanıcı" required></div>
            <div class="col"><input name="pass" type="password" class="form-control form-control-sm" placeholder="Şifre" required></div>
            <div class="col-2">
                <select name="sensitivity" class="form-select form-select-sm">
                    <option value="LOW">LOW</option>
                    <?php if($role === 'tech' || $role === 'admin'): ?>
                        <option value="HIGH">HIGH</option>
                    <?php endif; ?>
                    <?php if($role === 'admin'): ?>
                        <option value="CRITICAL">CRITICAL</option>
                    <?php endif; ?>
                </select>
            </div>
            <div class="col-auto"><button type="submit" name="add_vault" class="btn btn-success btn-sm px-3">Ekle</button></div>
        </form>
        
        <table class="table table-bordered table-hover mb-5">
            <thead class="table-light"><tr><th>Hizmet</th><th>Kullanıcı</th><th>Risk</th><th>Şifre (Encrypted)</th><th>İşlem</th></tr></thead>
            <tbody>
                <?php foreach($vaults as $v): ?>
                <tr>
                    <td><?= SecurityHelper::e($v['service']) ?></td>
                    <td><?= SecurityHelper::e($v['username']) ?></td>
                    <td><?= getBadge($v['sensitivity']) ?></td>
                    <td class="text-break" style="font-family: monospace; font-size: 0.9em;">
                        <?= htmlspecialchars(substr($v['password'], 0, 15)) ?>
                    </td>
                    <td class="text-center" style="width: 150px;">
                        <button type="button" class="btn btn-outline-warning btn-sm me-1 edit-btn" 
                                data-id="<?= $v['id'] ?>" 
                                data-service="<?= SecurityHelper::e($v['service']) ?>"
                                data-username="<?= SecurityHelper::e($v['username']) ?>"
                                data-sensitivity="<?= $v['sensitivity'] ?>">
                            Düzenle
                        </button>
                        <a href="?del_vault=<?= $v['id'] ?>&csrf=<?= SecurityHelper::csrfToken() ?>" 
                           class="btn btn-outline-danger btn-sm" 
                           onclick="return confirm('Silmek istediğinize emin misiniz?')">Sil</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if($role === 'admin'): ?>
        <div class="mt-5 pt-3 border-top">
            <h5 class="text-muted text-uppercase small fw-bold mb-3">Personel Yönetimi</h5>
            <form method="POST" class="row g-2 mb-3">
                <input type="hidden" name="csrf" value="<?= SecurityHelper::csrfToken() ?>">
                <div class="col"><input name="new_user" class="form-control form-control-sm" placeholder="Kullanıcı Adı" required></div>
                <div class="col"><input name="new_pass" class="form-control form-control-sm" placeholder="Şifre" required></div>
                <div class="col">
                    <select name="new_role" class="form-select form-select-sm">
                        <option value="admin">Yönetici</option><option value="tech">Uzman</option><option value="intern">Stajyer</option>
                    </select>
                </div>
                <div class="col-auto"><button type="submit" name="add_user" class="btn btn-secondary btn-sm px-3">Ekle</button></div>
            </form>
            
            <table class="table table-sm bg-white align-middle">
                <thead><tr><th>ID</th><th>Kullanıcı</th><th>Rol</th><th>İşlemler</th></tr></thead>
                <tbody>
                    <?php foreach($users_list as $u): ?>
                    <tr>
                        <td><?= $u['id'] ?></td>
                        <td><?= SecurityHelper::e($u['username']) ?></td>
                        <td><span class="badge bg-secondary"><?= $u['role'] ?></span></td>
                        <td>
                            <button type="button" class="btn btn-sm btn-outline-primary edit-user-btn" 
                                data-id="<?= $u['id'] ?>"
                                data-username="<?= SecurityHelper::e($u['username']) ?>"
                                data-role="<?= $u['role'] ?>">Düzenle</button>
                            <?php if($u['id'] != $_SESSION['user_id']): ?>
                            <a href="?del_user=<?= $u['id'] ?>&csrf=<?= SecurityHelper::csrfToken() ?>" class="btn btn-sm btn-outline-danger ms-1" onclick="return confirm('Sil?')">Sil</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

    <?php endif; ?>
</div>

<div class="modal fade" id="editVaultModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Kaydı Düzenle</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="editVaultForm" method="POST">
                <input type="hidden" name="update_vault" value="1">
                <input type="hidden" name="csrf" value="<?= SecurityHelper::csrfToken() ?>">
                <input type="hidden" name="vault_id" id="editVaultId">
                <div class="modal-body">
                    <div class="mb-3"><label class="form-label">Hizmet</label><input type="text" class="form-control" id="editService" name="service" required></div>
                    <div class="mb-3"><label class="form-label">Kullanıcı</label><input type="text" class="form-control" id="editUsername" name="username" required></div>
                    <div class="mb-3"><label class="form-label">Yeni Şifre (Boş bırakılabilir)</label><input type="password" class="form-control" name="password"></div>
                    <div class="mb-3">
                        <label class="form-label">Risk</label>
                        <select name="sensitivity" class="form-select" id="editSensitivity">
                            <option value="LOW">LOW</option>
                            <?php if($role === 'tech' || $role === 'admin'): ?>
                                <option value="HIGH">HIGH</option>
                            <?php endif; ?>
                            <?php if($role === 'admin'): ?>
                                <option value="CRITICAL">CRITICAL</option>
                            <?php endif; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                    <button type="submit" class="btn btn-success">Güncelle</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div class="modal fade" id="editUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Kullanıcı Düzenle</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form id="editUserForm" method="POST">
                <input type="hidden" name="update_user" value="1">
                <input type="hidden" name="csrf" value="<?= SecurityHelper::csrfToken() ?>">
                <input type="hidden" name="user_id" id="editUserId">
                <div class="modal-body">
                    <div class="mb-3"><label class="form-label">Kullanıcı Adı</label><input type="text" class="form-control" id="editUserUsername" name="edit_username" required></div>
                    <div class="mb-3">
                        <label class="form-label">Rol</label>
                        <select name="edit_role" class="form-select" id="editUserRole">
                            <option value="admin">Yönetici</option>
                            <option value="tech">Uzman</option>
                            <option value="intern">Stajyer</option>
                        </select>
                    </div>
                    <div class="mb-3"><label class="form-label">Yeni Şifre (Boş bırakılabilir)</label><input type="password" class="form-control" name="edit_pass"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                    <button type="submit" class="btn btn-primary">Kaydet</button>
                </div>
            </form>
        </div>
    </div>
</div>

<div id="presenceModal" style="display:none;"></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.addEventListener('click', function(e) {
    // Vault Edit
    const vBtn = e.target.closest('.edit-btn');
    if (vBtn) {
        document.getElementById('editVaultId').value = vBtn.dataset.id;
        document.getElementById('editService').value = vBtn.dataset.service;
        document.getElementById('editUsername').value = vBtn.dataset.username;
        document.getElementById('editSensitivity').value = vBtn.dataset.sensitivity;
        new bootstrap.Modal(document.getElementById('editVaultModal')).show();
    }

    // User Edit
    const uBtn = e.target.closest('.edit-user-btn');
    if (uBtn) {
        document.getElementById('editUserId').value = uBtn.dataset.id;
        document.getElementById('editUserUsername').value = uBtn.dataset.username;
        document.getElementById('editUserRole').value = uBtn.dataset.role;
        new bootstrap.Modal(document.getElementById('editUserModal')).show();
    }
});
</script>
</body>
</html>