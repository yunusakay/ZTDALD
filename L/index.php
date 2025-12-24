<?php
session_start();
require '../config.php';

if (isset($_GET['ping'])) { http_response_code(204); exit; }

$msg = "";
$user = $_SESSION['user'] ?? null;
$role = $_SESSION['role'] ?? null;

if (isset($_POST['login'])) {
    $u = $_POST['user'];
    $p = $_POST['pass'];
    
    // VULNERABLE: Direct SQL Injection
    $sql = "SELECT * FROM l_users WHERE username = '$u' AND password = '$p'";
    
    try {
        $stmt = $pdo->query($sql);
        if ($stmt) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                $_SESSION['user'] = $row['username'];
                $_SESSION['role'] = $row['role'];
                $_SESSION['user_id'] = $row['id'];
                header("Location: index.php");
                exit;
            }
        }
        $msg = "Hatalı kullanıcı adı veya şifre!";
    } catch (PDOException $e) {
        $msg = "SQL Hatası: " . $e->getMessage();
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}

if ($user) {
    // 1. Kasa Ekleme
    if (isset($_POST['add_vault'])) {
        $srv = $_POST['service'];
        $usr = $_POST['login'];
        $pwd = $_POST['pass'];
        $sen = $_POST['sensitivity'];
        
        $pdo->exec("INSERT INTO l_vault (service, username, password, sensitivity) VALUES ('$srv', '$usr', '$pwd', '$sen')");
        $msg = "Kayıt eklendi.";
    }

    // 2. Kasa Güncelleme
    if (isset($_POST['update_vault'])) {
        $id = $_POST['vault_id'];
        $srv = $_POST['service'];
        $usr = $_POST['username'];
        $pwd = $_POST['password'];
        $sen = $_POST['sensitivity'];
        
        $sql = "UPDATE l_vault SET service='$srv', username='$usr', sensitivity='$sen'";
        if (!empty($pwd)) $sql .= ", password='$pwd'";
        $sql .= " WHERE id=$id";
        
        $pdo->exec($sql);
        $msg = "Kayıt güncellendi.";
    }

    // 3. Kasa Silme
    if (isset($_GET['del_vault'])) {
        $id = $_GET['del_vault'];
        $pdo->exec("DELETE FROM l_vault WHERE id = $id");
        $msg = "Kayıt silindi.";
    }

    // 4. Kullanıcı Ekleme
    if (isset($_POST['add_user'])) {
        $nu = $_POST['new_user'];
        $np = $_POST['new_pass'];
        $nr = $_POST['new_role'];
        $pdo->exec("INSERT INTO l_users (username, password, role) VALUES ('$nu', '$np', '$nr')");
        $msg = "Personel eklendi.";
    }

    // 5. Kullanıcı Güncelleme - YENİ (Vulnerable)
    if (isset($_POST['update_user'])) {
        $uid = $_POST['user_id'];
        $unu = $_POST['edit_username'];
        $unr = $_POST['edit_role'];
        $unp = $_POST['edit_pass'];
        
        // ZAFİYET: SQL Injection + Yetki Kontrolü Yok
        $sql = "UPDATE l_users SET username='$unu', role='$unr'";
        if (!empty($unp)) $sql .= ", password='$unp'";
        $sql .= " WHERE id=$uid";
        
        $pdo->exec($sql);
        $msg = "Kullanıcı güncellendi.";
    }
    
    // 6. Kullanıcı Silme
    if (isset($_GET['del_user'])) {
        $id = $_GET['del_user'];
        $pdo->exec("DELETE FROM l_users WHERE id = $id");
        $msg = "Personel silindi.";
    }
}

$vaults = [];
$users_list = [];
if ($user) {
    $vaults = $pdo->query("SELECT * FROM l_vault")->fetchAll(PDO::FETCH_ASSOC);
    $users_list = $pdo->query("SELECT * FROM l_users")->fetchAll(PDO::FETCH_ASSOC);
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
    <title>LEGACY VAULT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body { background-color: #f8f9fa; }</style>
</head>
<body class="p-4">

<div class="container bg-white p-4 shadow rounded" style="max-width: 900px;">
    <?php if (!$user): ?>
        <h3 class="text-center mb-4 text-danger">LEGACY VAULT</h3>
        <?php if($msg): ?><div class="alert alert-danger text-center"><?= $msg ?></div><?php endif; ?>
        <form method="POST" class="w-50 mx-auto">
            <input type="text" name="user" class="form-control mb-2" placeholder="Kullanıcı Adı">
            <input type="password" name="pass" class="form-control mb-3" placeholder="Şifre">
            <button type="submit" name="login" class="btn btn-danger w-100">Giriş Yap</button>
        </form>
    <?php else: ?>
        <div class="d-flex justify-content-between border-bottom pb-3 mb-4">
            <h4 class="m-0">Legacy Vault <span class="badge bg-secondary fs-6"><?= strtoupper($role) ?></span></h4>
            <div>
                <span class="me-2 text-muted">User: <?= $user ?></span>
                <a href="?logout" class="btn btn-outline-danger btn-sm">Çıkış</a>
            </div>
        </div>
        
        <?php if($msg): ?><div class="alert alert-light border"><?= $msg ?></div><?php endif; ?>

        <h6 class="text-muted text-uppercase small fw-bold mb-3">Yeni Kayıt Ekle</h6>
        <form method="POST" class="row g-2 mb-5">
            <input type="hidden" name="csrf" value="dummy_token_legacy">
            <div class="col"><input name="service" class="form-control form-control-sm" placeholder="Hizmet"></div>
            <div class="col"><input name="login" class="form-control form-control-sm" placeholder="Kullanıcı"></div>
            <div class="col"><input name="pass" class="form-control form-control-sm" placeholder="Şifre"></div>
            <div class="col-2">
                <select name="sensitivity" class="form-select form-select-sm">
                    <option value="LOW">LOW</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
                </select>
            </div>
            <div class="col-auto"><button type="submit" name="add_vault" class="btn btn-dark btn-sm px-3">Ekle</button></div>
        </form>
        
        <table class="table table-bordered table-hover mb-5">
            <thead class="table-light"><tr><th>Hizmet</th><th>Kullanıcı</th><th>Risk</th><th>Şifre</th><th>İşlem</th></tr></thead>
            <tbody>
                <?php foreach($vaults as $v): ?>
                <tr>
                    <td><?= $v['service'] ?></td>
                    <td><?= $v['username'] ?></td>
                    <td><?= getBadge($v['sensitivity']) ?></td>
                    <td><?= $v['password'] ?></td>
                    <td class="text-center" style="width: 150px;">
                        <button type="button" class="btn btn-outline-warning btn-sm me-1 edit-btn" 
                                data-id="<?= $v['id'] ?>" 
                                data-service="<?= htmlspecialchars($v['service']) ?>"
                                data-username="<?= htmlspecialchars($v['username']) ?>"
                                data-password="<?= htmlspecialchars($v['password']) ?>"
                                data-sensitivity="<?= $v['sensitivity'] ?>">
                            Düzenle
                        </button>
                        <a href="?del_vault=<?= $v['id'] ?>" 
                           class="btn btn-outline-danger btn-sm" 
                           onclick="return confirm('Silmek istediğinize emin misiniz?')">Sil</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if($role === 'admin' || $role === 'intern' || $role === 'tech'): ?>
        <div class="mt-5 pt-3 border-top">
            <h5 class="text-muted text-uppercase small fw-bold mb-3">Personel Yönetimi</h5>
            <form method="POST" class="row g-2 mb-3">
                <div class="col"><input name="new_user" class="form-control form-control-sm" placeholder="Kullanıcı Adı"></div>
                <div class="col"><input name="new_pass" class="form-control form-control-sm" placeholder="Şifre"></div>
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
                        <td><?= $u['username'] ?></td>
                        <td><span class="badge bg-secondary"><?= $u['role'] ?></span></td>
                        <td>
                            <button type="button" class="btn btn-sm btn-outline-primary edit-user-btn" 
                                data-id="<?= $u['id'] ?>"
                                data-username="<?= $u['username'] ?>"
                                data-role="<?= $u['role'] ?>">Düzenle</button>
                            <a href="?del_user=<?= $u['id'] ?>" class="btn btn-sm btn-outline-danger ms-1" onclick="return confirm('Sil?')">Sil</a>
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
                <input type="hidden" name="vault_id" id="editVaultId">
                <div class="modal-body">
                    <div class="mb-3"><label class="form-label">Hizmet</label><input type="text" class="form-control" id="editService" name="service"></div>
                    <div class="mb-3"><label class="form-label">Kullanıcı</label><input type="text" class="form-control" id="editUsername" name="username"></div>
                    <div class="mb-3"><label class="form-label">Şifre</label><input type="text" class="form-control" id="editPassword" name="password"></div>
                    <div class="mb-3">
                        <label class="form-label">Risk</label>
                        <select name="sensitivity" class="form-select" id="editSensitivity">
                            <option value="LOW">LOW</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                    <button type="submit" class="btn btn-primary">Güncelle</button>
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
                <input type="hidden" name="user_id" id="editUserId">
                <div class="modal-body">
                    <div class="mb-3"><label class="form-label">Kullanıcı Adı</label><input type="text" class="form-control" id="editUserUsername" name="edit_username"></div>
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

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.addEventListener('click', function(e) {
    // Vault Edit
    const vBtn = e.target.closest('.edit-btn');
    if (vBtn) {
        document.getElementById('editVaultId').value = vBtn.dataset.id;
        document.getElementById('editService').value = vBtn.dataset.service;
        document.getElementById('editUsername').value = vBtn.dataset.username;
        document.getElementById('editPassword').value = vBtn.dataset.password;
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