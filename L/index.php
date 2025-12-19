<?php
session_start();
require '../config.php';

if (isset($_GET['logout'])) { session_destroy(); header("Location: index.php"); exit; }

if (isset($_POST['login'])) {
    $stmt = $pdo->prepare("SELECT * FROM l_users WHERE username = '{$_POST['user']}' AND password = '{$_POST['pass']}'");
    $stmt->execute();
    $user = $stmt->fetch();
    if ($user) { $_SESSION['user'] = $user['username']; $_SESSION['role'] = $user['role']; }
}

$user = $_SESSION['user'] ?? null;
$role = $_SESSION['role'] ?? null;

if ($user && isset($_POST['add_vault'])) {
    $service = $_POST['service'];
    $login = $_POST['login'];
    $pass = $_POST['pass'];
    $sensitivity = $_POST['sensitivity'];
    $pdo->query("INSERT INTO l_vault (service, username, password, sensitivity) VALUES ('$service', '$login', '$pass', '$sensitivity')");
    $msg = "Kayıt Başarılı.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_vault'])) {
    $id = (int)($_POST['vault_id'] ?? 0);
    $service = $_POST['service'] ?? '';
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $sensitivity = $_POST['sensitivity'] ?? 'LOW';
    
    if ($id > 0 && !empty($service) && !empty($username) && !empty($password)) {
        $stmt = $pdo->prepare("UPDATE l_vault SET service = ?, username = ?, password = ?, sensitivity = ? WHERE id = ?");
        $stmt->execute([$service, $username, $password, $sensitivity, $id]);
        $msg = "Kasa kaydı güncellendi.";
    } else {
        $msg = "Hata: Eksik bilgi.";
    }
}

if (isset($_GET['del_vault'])) {
    $id = (int)$_GET['del_vault'];
    $pdo->exec("DELETE FROM l_vault WHERE id = $id");
    $msg = "Kasa kaydı silindi.";
}

if ($user && isset($_POST['add_user'])) {
    if ($role === 'admin') {
        $nu = trim($_POST['new_user'] ?? '');
        $np = $_POST['new_pass'] ?? '';
        $nr = $_POST['new_role'] ?? 'intern';

        // Basic input validation
        if (empty($nu) || empty($np)) {
            $msg = "Kullanıcı adı ve şifre zorunludur!";
        } elseif (strlen($np) < 4) {
            $msg = "Şifre en az 4 karakter olmalıdır!";
        } elseif (!in_array($nr, ['admin', 'tech', 'intern'], true)) {
            $msg = "Geçersiz rol seçildi!";
        } else {
            // Check if user already exists
            $check = $pdo->query("SELECT id FROM l_users WHERE username = '" . $pdo->quote($nu) . "'")->fetch();
            if ($check) {
                $msg = "Bu kullanıcı adı zaten kullanılıyor!";
            } else {
                $pdo->query("INSERT INTO l_users (username, password, role) VALUES ('" . $pdo->quote($nu) . "', '" . $pdo->quote($np) . "', '" . $pdo->quote($nr) . "')");
                $msg = "Personel eklendi.";
            }
        }
    } else {
        $msg = "Sadece admin personel ekleyebilir!";
    }
}

// Handle update user
if ($user && isset($_POST['update_user'])) {
    if ($role === 'admin') {
        $user_id = (int)($_POST['user_id'] ?? 0);
        $nu = trim($_POST['edit_username'] ?? '');
        $nr = $_POST['edit_role'] ?? 'intern';
        $np = $_POST['edit_password'] ?? '';
        
        // Basic validation
        if ($user_id <= 0) {
            $msg = "Geçersiz kullanıcı ID'si.";
        } elseif (empty($nu)) {
            $msg = "Kullanıcı adı boş olamaz.";
        } elseif (!in_array($nr, ['admin', 'tech', 'intern'], true)) {
            $msg = "Geçersiz rol seçildi.";
        } else {
            // Check if user exists
            $existing = $pdo->query("SELECT * FROM l_users WHERE id = " . $user_id)->fetch();
            if (!$existing) {
                $msg = "Kullanıcı bulunamadı.";
            } else {
                // Check if new username is already taken by another user
                $duplicate = $pdo->query("SELECT id FROM l_users WHERE username = '" . $pdo->quote($nu) . "' AND id != " . $user_id)->fetch();
                if ($duplicate) {
                    $msg = "Bu kullanıcı adı zaten kullanılıyor.";
                } else {
                    // Build update query
                    $updates = [
                        "username = '" . $pdo->quote($nu) . "'",
                        "role = '" . $pdo->quote($nr) . "'"
                    ];
                    
                    // Only update password if provided
                    if (!empty($np)) {
                        if (strlen($np) < 4) {
                            $msg = "Şifre en az 4 karakter olmalıdır.";
                        } else {
                            $updates[] = "password = '" . $pdo->quote($np) . "'";
                        }
                    }
                    
                    if (!isset($msg)) {
                        $query = "UPDATE l_users SET " . implode(", ", $updates) . " WHERE id = " . $user_id;
                        $pdo->query($query);
                        $msg = "Kullanıcı bilgileri güncellendi.";
                        
                        // If editing own account, update session
                        if ($user_id === $user_id) {
                            $_SESSION['user'] = $nu;
                            $_SESSION['role'] = $nr;
                        }
                    }
                }
            }
        }
    } else {
        $msg = "Sadece admin kullanıcı düzenleyebilir!";
    }
}

if (isset($_GET['del_user'])) {
    $id = $_GET['del_user'];
    $pdo->query("DELETE FROM l_users WHERE id = $id");
    $msg = "Personel Silindi.";
}

if ($user) {
    $vault = $pdo->query("SELECT * FROM l_vault")->fetchAll();
    $users = $pdo->query("SELECT * FROM l_users")->fetchAll();
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>LEGACY VAULT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light p-4">
<div class="container bg-white p-4 shadow rounded" style="max-width: 900px;">

    <?php if (!$user): ?>
        <h4 class="text-center mb-4">Giriş Yap</h4>
        <form method="POST" class="w-50 mx-auto">
            <input type="text" name="user" class="form-control mb-2" placeholder="Kullanıcı Adı">
            <input type="password" name="pass" class="form-control mb-3" placeholder="Şifre">
            <button type="submit" name="login" class="btn btn-dark w-100">Giriş</button>
        </form>
    <?php else: ?>
        
        <div class="d-flex justify-content-between border-bottom pb-3 mb-4">
            <h4 class="m-0">Kurumsal Kasa <span class="badge bg-secondary fs-6"><?= strtoupper($role) ?></span></h4>
            <a href="?logout" class="btn btn-outline-danger btn-sm">Çıkış</a>
        </div>

        <?php if(isset($msg)) echo "<div class='alert alert-light border mb-4'>$msg</div>"; ?>

        <h6 class="text-muted text-uppercase small fw-bold mb-3">Yeni Şifre Ekle</h6>
        <form method="POST" class="row g-2 mb-5">
            <div class="col"><input name="service" class="form-control form-control-sm" placeholder="Hizmet" required></div>
            <div class="col"><input name="login" class="form-control form-control-sm" placeholder="Kullanıcı" required></div>
            <div class="col"><input name="pass" class="form-control form-control-sm" placeholder="Şifre" required></div>
            <div class="col-2">
                <select name="sensitivity" class="form-select form-select-sm">
                    <option value="LOW">LOW</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
                </select>
            </div>
            <div class="col-auto"><button type="submit" name="add_vault" class="btn btn-dark btn-sm px-3">Ekle</button></div>
        </form>

        <table class="table table-bordered table-hover mb-5">
            <thead class="table-light"><tr><th>Hizmet</th><th>Kullanıcı</th><th>Seviye</th><th>Şifre</th><th></th></tr></thead>
            <tbody>
                <?php foreach($vault as $v): ?>
                <tr>
                    <td><?= $v['service'] ?></td>
                    <td><?= $v['username'] ?></td>
                    <td><span class="badge <?= $v['sensitivity']=='LOW'?'bg-success':($v['sensitivity']=='HIGH'?'bg-warning':'bg-danger') ?>"><?= $v['sensitivity'] ?></span></td>
                    <td><?= $v['password'] ?></td>
                    <td class="text-center">
                    <button type="button" class="btn btn-outline-warning btn-sm me-1 edit-btn" 
                            data-id="<?= (int)$v['id'] ?>" 
                            data-service="<?= htmlspecialchars($v['service'], ENT_QUOTES) ?>"
                            data-username="<?= htmlspecialchars($v['username']) ?>"
                            data-password="<?= htmlspecialchars($v['password']) ?>"
                            data-sensitivity="<?= htmlspecialchars($v['sensitivity']) ?>">
                        Düzenle
                    </button>
                    <a href="?del_vault=<?= $v['id'] ?>" class="btn btn-outline-danger btn-sm" onclick="return confirm('Bu kaydı silmek istediğinize emin misiniz?')">
                        Sil
                    </a>
                </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="mt-5 pt-3 border-top">
            <h5 class="text-muted text-uppercase small fw-bold mb-3">Personel Yönetimi</h5>
            <form method="POST" class="row g-2 mb-3">
                <div class="col"><input name="new_user" class="form-control form-control-sm" placeholder="Kullanıcı Adı" required></div>
                <div class="col"><input name="new_pass" class="form-control form-control-sm" placeholder="Şifre" required></div>
                <div class="col">
                    <select name="new_role" class="form-select form-select-sm">
                        <option value="admin">Yönetici</option><option value="tech">Uzman</option><option value="intern">Stajyer</option>
                    </select>
                </div>
                <div class="col-auto"><button type="submit" name="add_user" class="btn btn-secondary btn-sm px-3">Ekle</button></div>
            </form>

            <table class="table table-sm bg-white">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Kullanıcı</th>
                        <th>Rol</th>
                        <th>İşlemler</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($users as $u): 
                        $isCurrentUser = ($u['username'] === ($_SESSION['user'] ?? ''));
                    ?>
                    <tr>
                        <td><?= htmlspecialchars($u['id']) ?></td>
                        <td><?= htmlspecialchars($u['username']) ?></td>
                        <td>
                            <span class="badge bg-secondary text-dark user-select-none" data-user-id="<?= $u['id'] ?>" style="cursor: pointer; min-width: 80px; display: inline-block; text-align: center;">
                                <?= htmlspecialchars($u['role']) ?>
                            </span>
                            <select class="form-select form-select-sm d-none role-select" data-user-id="<?= $u['id'] ?>" style="width: auto; min-width: 80px; display: inline-block;">
                                <option value="admin" <?= $u['role'] === 'admin' ? 'selected' : '' ?>>admin</option>
                                <option value="tech" <?= $u['role'] === 'tech' ? 'selected' : '' ?>>tech</option>
                                <option value="intern" <?= $u['role'] === 'intern' ? 'selected' : '' ?>>intern</option>
                            </select>
                        </td>
                        <td class="d-flex gap-1">
                            <button type="button" class="btn btn-sm btn-outline-primary edit-user" 
                                    data-id="<?= $u['id'] ?>"
                                    data-username="<?= htmlspecialchars($u['username']) ?>"
                                    data-role="<?= htmlspecialchars($u['role']) ?>">
                                Düzenle
                            </button>
                            <?php if (!$isCurrentUser): ?>
                            <a href="?del_user=<?= $u['id'] ?>" 
                               class="btn btn-sm btn-outline-danger" 
                               onclick="return confirm('Bu kullanıcıyı silmek istediğinize emin misiniz?')">
                                Sil
                            </a>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <!-- Edit User Modal -->
            <div class="modal fade" id="editUserModal" tabindex="-1" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Kullanıcı Düzenle</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                        </div>
                        <form method="POST" id="editUserForm">
                            <input type="hidden" name="update_user" value="1">
                            <input type="hidden" name="user_id" id="editUserId">
                            
                            <div class="modal-body">
                                <div class="mb-3">
                                    <label for="editUsername" class="form-label">Kullanıcı Adı</label>
                                    <input type="text" class="form-control" id="editUsername" name="edit_username" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="editRole" class="form-label">Rol</label>
                                    <select class="form-select" id="editRole" name="edit_role" required>
                                        <option value="admin">Yönetici</option>
                                        <option value="tech">Uzman</option>
                                        <option value="intern">Stajyer</option>
                                    </select>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="editPassword" class="form-label">Yeni Şifre (Değiştirmek istemiyorsanız boş bırakın)</label>
                                    <input type="password" class="form-control" id="editPassword" name="edit_password" autocomplete="new-password">
                                    <div class="form-text">En az 4 karakter olmalıdır.</div>
                                </div>
                            </div>
                            
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">İptal</button>
                                <button type="submit" class="btn btn-primary">Kaydet</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <script>
            // Handle edit user button click
            document.querySelectorAll('.edit-user').forEach(button => {
                button.addEventListener('click', function() {
                    const userId = this.dataset.id;
                    const username = this.dataset.username;
                    const role = this.dataset.role;
                    
                    // Set form values
                    document.getElementById('editUserId').value = userId;
                    document.getElementById('editUsername').value = username;
                    document.getElementById('editRole').value = role;
                    document.getElementById('editPassword').value = '';
                    
                    // Show modal
                    const modal = new bootstrap.Modal(document.getElementById('editUserModal'));
                    modal.show();
                });
            });
            
            // Handle role change
            document.querySelectorAll('[data-user-id]').forEach(badge => {
                badge.addEventListener('click', function() {
                    const userId = this.dataset.userId;
                    this.classList.add('d-none');
                    document.querySelector(`[data-user-id="${userId}"] + select`).classList.remove('d-none');
                });
            });
            
            // Handle role select change
            document.querySelectorAll('[data-user-id] + select').forEach(select => {
                select.addEventListener('change', function() {
                    const userId = this.dataset.userId;
                    const newRole = this.value;
                    
                    // Update role via form submission
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.innerHTML = `
                        <input type="hidden" name="update_user" value="1">
                        <input type="hidden" name="user_id" value="${userId}">
                        <input type="hidden" name="edit_username" value="${document.querySelector(`.edit-user[data-id="${userId}"]`).dataset.username}">
                        <input type="hidden" name="edit_role" value="${newRole}">
                    `;
                    
                    document.body.appendChild(form);
                    form.submit();
                });
                
                // Hide select when clicking outside
                document.addEventListener('click', function(e) {
                    if (!e.target.closest('[data-user-id] + select') && !e.target.closest('[data-user-id]')) {
                        document.querySelectorAll('[data-user-id] + select').forEach(sel => {
                            if (!sel.classList.contains('d-none')) {
                                sel.classList.add('d-none');
                                document.querySelector(`[data-user-id="${sel.dataset.userId}"]`).classList.remove('d-none');
                            }
                        });
                    }
                });
            });
            </script>
            
    <?php endif; ?>

    <!-- Edit Vault Modal -->
    <div class="modal fade" id="editVaultModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Kaydı Düzenle</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <form id="editVaultForm" method="POST">
                    <input type="hidden" name="update_vault" value="1">
                    <input type="hidden" name="vault_id" id="editVaultId">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Hizmet</label>
                            <input type="text" class="form-control" id="editService" name="service" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Kullanıcı Adı</label>
                            <input type="text" class="form-control" id="editUsername" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Şifre</label>
                            <input type="text" class="form-control" id="editPassword" name="password" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Risk Seviyesi</label>
                            <select name="sensitivity" class="form-select" id="editSensitivity">
                                <option value="LOW">LOW</option>
                                <option value="HIGH">HIGH</option>
                                <option value="CRITICAL">CRITICAL</option>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Handle edit button click
    document.addEventListener('click', function(e) {
        const editBtn = e.target.closest('.edit-btn');
        if (editBtn) {
            document.getElementById('editVaultId').value = editBtn.dataset.id;
            document.getElementById('editService').value = editBtn.dataset.service;
            document.getElementById('editUsername').value = editBtn.dataset.username;
            document.getElementById('editPassword').value = editBtn.dataset.password;
            document.getElementById('editSensitivity').value = editBtn.dataset.sensitivity;
            
            const modal = new bootstrap.Modal(document.getElementById('editVaultModal'));
            modal.show();
        }
    });
    </script>
</div>
</body>
</html>