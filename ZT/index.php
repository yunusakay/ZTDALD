<?php
require __DIR__ . '/../security_helper.php';
SecurityHelper::init();
require __DIR__ . '/../database.php';
$db = Database::getInstance();

if (isset($_GET['ping'])) {
    if (isset($_SESSION['user'])) {
        $_SESSION['__last_activity'] = time();
    }
    http_response_code(204);
    exit;
}

if (isset($_GET['reveal_vault'])) {
    header('Content-Type: application/json; charset=utf-8');

    if (!isset($_SESSION['user'], $_SESSION['role'])) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Oturum yok']);
        exit;
    }

    if (!SecurityHelper::verifyCsrf($_GET['csrf'] ?? null)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Geçersiz istek (CSRF)']);
        exit;
    }

    $role = (string)($_SESSION['role'] ?? '');
    $id = (int)($_GET['reveal_vault'] ?? 0);
    if ($id <= 0) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Geçersiz kayıt']);
        exit;
    }

    $items = $db->select('zt_vault', ['id' => $id]);
    $item = $items[0] ?? null;
    if (!$item) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'Kayıt bulunamadı']);
        exit;
    }

    $sens = (string)($item['sensitivity'] ?? 'LOW');
    $allowed = false;
    if ($role === 'admin') {
        $allowed = true;
    } elseif ($role === 'tech' && $sens !== 'CRITICAL') {
        $allowed = true;
    } elseif ($role === 'intern' && $sens === 'LOW') {
        $allowed = true;
    }

    if (!$allowed) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'Yetkisiz']);
        exit;
    }

    $cfg = $db->getConfig();
    $key = (string)($cfg['security']['vault']['key'] ?? 'change-me');
    $cipher = (string)($cfg['security']['vault']['cipher'] ?? 'AES-256-CBC');
    $iv = (string)($cfg['security']['vault']['iv'] ?? 'change-me-too');
    $k = hash('sha256', $key, true);
    $i = substr(hash('sha256', $iv, true), 0, 16);

    $enc = (string)($item['password'] ?? '');
    $plain = openssl_decrypt($enc, $cipher, $k, 0, $i);
    if ($plain === false) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Şifre çözme hatası']);
        exit;
    }

    echo json_encode(['ok' => true, 'password' => $plain]);
    exit;
}

if (isset($_GET['logout'])) { SecurityHelper::logout(); }

if (isset($_POST['login'])) {
    if (SecurityHelper::rateLimited('login_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 6, 60)) {
        $msg = "ENGEL: Çok fazla giriş denemesi. 1 dakika bekleyin.";
    } else {
        $u_name = trim($_POST['user'] ?? '');
        $u_pass = $_POST['pass'] ?? '';

        if (empty($u_name) || empty($u_pass)) {
            $msg = "ENGEL: Kullanıcı adı ve şifre zorunludur.";
        } elseif (strlen($u_name) < 3 || strlen($u_name) > 50) {
            $msg = "ENGEL: Kullanıcı adı 3-50 karakter arasında olmalı.";
        } else {
            $users = $db->select('zt_users', ['username' => $u_name]);
            $user = $users[0] ?? null;

            if ($user && password_verify($u_pass, $user['password'])) {
                $_SESSION['user'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['user_id'] = $user['id'];
                session_regenerate_id(true);
                header('Location: index.php');
                exit;
            } else {
                $msg = 'Hatalı kullanıcı adı veya şifre';
            }
        }
    }
}

$user = $_SESSION['user'] ?? null;
$role = $_SESSION['role'] ?? null;

if ($user && isset($_POST['add_vault'])) {
    if (!SecurityHelper::verifyCsrf($_POST['csrf'] ?? null)) {
        $msg = "ENGEL: Geçersiz istek (CSRF).";
    } else {
        // Input validation rules
        $validation = SecurityHelper::validateInputs($_POST, [
            'service' => [
                'type' => 'alnum_space',
                'required' => true,
                'max_length' => 100,
                'message' => 'Hizmet adı geçersiz (sadece harf, rakam ve boşluk)'
            ],
            'login' => [
                'type' => 'username',
                'required' => true,
                'max_length' => 100,
                'message' => 'Kullanıcı adı geçersiz (sadece harf, rakam, -_.@ karakterleri)'
            ],
            'pass' => [
                'type' => 'string',
                'required' => true,
                'min_length' => 4,
                'message' => 'Şifre en az 4 karakter olmalıdır'
            ],
            'sensitivity' => [
                'type' => 'string',
                'required' => true,
                'in_array' => ['LOW', 'HIGH', 'CRITICAL'],
                'message' => 'Geçersiz risk seviyesi'
            ]
        ]);

        if (!$validation['valid']) {
            $msg = 'Hata: ' . implode(', ', $validation['errors']);
        } else {
            $data = $validation['data'];
            $s = $data['service'];
            $l = $data['login'];
            $p = $data['pass'];
            $sen = $data['sensitivity'];
            
            $cfg = $db->getConfig();
            $key = (string)($cfg['security']['vault']['key'] ?? 'change-me');
            $cipher = (string)($cfg['security']['vault']['cipher'] ?? 'AES-256-CBC');
            $iv = (string)($cfg['security']['vault']['iv'] ?? 'change-me-too');
            $k = hash('sha256', $key, true);
            $i = substr(hash('sha256', $iv, true), 0, 16);
            $encrypted = openssl_encrypt($p, $cipher, $k, 0, $i);
            
            if ($encrypted === false) {
                $msg = "ENGEL: Şifreleme hatası.";
            } else {
                $db->insert('zt_vault', [
                    'service' => $s,
                    'username' => $l,
                    'password' => $encrypted,
                    'sensitivity' => $sen
                ]);
                $msg = "Kasa kaydı eklendi.";
            }
        }
    }
}

if ($user && isset($_GET['del_vault'])) {
    if (!SecurityHelper::verifyCsrf($_GET['csrf'] ?? null)) {
        $msg = "ENGEL: Geçersiz istek (CSRF).";
    } else {
        $id = (int)$_GET['del_vault'];
        $items = $db->select('zt_vault', ['id' => $id], 'sensitivity');
        $item = $items[0] ?? null;

        if ($item && ($role == 'admin' || ($role == 'tech' && $item['sensitivity'] != 'CRITICAL'))) {
            $db->delete('zt_vault', ['id' => $id]);
            $msg = "Kasa kaydı silindi.";
        } else {
            $msg = "ENGEL: Bu işlem için yetkiniz yok veya kayıt bulunamadı.";
        }
    }
}

if ($user && isset($_POST['add_user'])) {
    if ($role === 'admin') {
        if (!SecurityHelper::verifyCsrf($_POST['csrf'] ?? null)) {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        } else {
            $nu = trim($_POST['new_user'] ?? '');
            $np = $_POST['new_pass'] ?? '';
            $nr = $_POST['new_role'] ?? 'intern';
            
            // Validate username
            if (empty($nu) || !preg_match('/^[a-zA-Z0-9_\-\.@]+$/', $nu)) {
                $msg = "Geçersiz kullanıcı adı formatı.";
            } 
            // Validate password
            elseif (strlen($np) < 4) {
                $msg = "Şifre en az 4 karakter olmalıdır.";
            } 
            // Validate role
            elseif (!in_array($nr, ['admin', 'tech', 'intern'], true)) {
                $msg = "Geçersiz rol seçildi.";
            } else {
                // Check if user already exists
                $existing = $db->select('zt_users', ['username' => $nu]);
                if (!empty($existing)) {
                    $msg = "Bu kullanıcı adı zaten kullanılıyor.";
                } else {
                    $db->insert('zt_users', [
                        'username' => $nu,
                        'password' => SecurityHelper::passwordHash($np),
                        'role' => $nr
                    ]);
                    $msg = "Yeni personel eklendi.";
                }
            }
        }
    } else {
        $msg = "ENGEL: Sadece admin personel ekleyebilir!";
    }
}

if ($user && isset($_POST['update_user'])) {
    if ($role === 'admin') {
        if (!SecurityHelper::verifyCsrf($_POST['csrf'] ?? null)) {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        } else {
            $user_id = (int)($_POST['user_id'] ?? 0);
            $nu = trim($_POST['edit_username'] ?? '');
            $nr = $_POST['edit_role'] ?? 'intern';
            $np = $_POST['edit_password'] ?? '';
            
            // Basic validation
            if ($user_id <= 0) {
                $msg = "Geçersiz kullanıcı ID'si.";
            } 
            // Validate username
            elseif (empty($nu) || !preg_match('/^[a-zA-Z0-9_\-\.@]+$/', $nu)) {
                $msg = "Geçersiz kullanıcı adı formatı.";
            } 
            // Validate role
            elseif (!in_array($nr, ['admin', 'tech', 'intern'], true)) {
                $msg = "Geçersiz rol seçildi.";
            } else {
                // Check if user exists
                $existing = $db->select('zt_users', ['id' => $user_id]);
                if (empty($existing)) {
                    $msg = "Kullanıcı bulunamadı.";
                } else {
                    // Check if new username is already taken by another user
                    $duplicate = $db->select('zt_users', ['username' => $nu, 'id[!]' => $user_id]);
                    if (!empty($duplicate)) {
                        $msg = "Bu kullanıcı adı zaten kullanılıyor.";
                    } else {
                        $updateData = [
                            'username' => $nu,
                            'role' => $nr
                        ];
                        
                        // Only update password if provided
                        if (!empty($np)) {
                            if (strlen($np) < 4) {
                                $msg = "Şifre en az 4 karakter olmalıdır.";
                            } else {
                                $updateData['password'] = SecurityHelper::passwordHash($np);
                            }
                        }
                        
                        if (!isset($msg)) {
                            $db->update('zt_users', $updateData, ['id' => $user_id]);
                            $msg = "Kullanıcı bilgileri güncellendi.";
                            
                            // If editing own account, update session
                            if ($user_id === ($_SESSION['user_id'] ?? null)) {
                                $_SESSION['user'] = $nu;
                                $_SESSION['role'] = $nr;
                            }
                        }
                    }
                }
            }
        }
    } else {
        $msg = "ENGEL: Sadece admin kullanıcı düzenleyebilir!";
    }
}

// Handle vault update
if ($user && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_vault'])) {
    header('Content-Type: application/json');
    
    if (!SecurityHelper::verifyCsrf($_POST['csrf'] ?? null)) {
        die(json_encode(['success' => false, 'error' => 'Geçersiz istek (CSRF)']));
    }

    // Input validation
    $validation = SecurityHelper::validateInputs($_POST, [
        'vault_id' => [
            'type' => 'int',
            'required' => true,
            'min' => 1,
            'message' => 'Geçersiz kayıt ID'
        ],
        'service' => [
            'type' => 'alnum_space',
            'required' => true,
            'max_length' => 100,
            'message' => 'Hizmet adı geçersiz (sadece harf, rakam ve boşluk)'
        ],
        'username' => [
            'type' => 'username',
            'required' => true,
            'max_length' => 100,
            'message' => 'Kullanıcı adı geçersiz (sadece harf, rakam, -_.@ karakterleri)'
        ],
        'sensitivity' => [
            'type' => 'string',
            'required' => true,
            'in_array' => ['LOW', 'HIGH', 'CRITICAL'],
            'message' => 'Geçersiz risk seviyesi'
        ]
    ]);

    if (!$validation['valid']) {
        die(json_encode(['success' => false, 'error' => implode(', ', $validation['errors'])]));
    }

    $vaultId = (int)$_POST['vault_id'];
    $service = trim($_POST['service']);
    $username = trim($_POST['username']);
    $newPassword = trim($_POST['new_password'] ?? '');
    $sensitivity = $_POST['sensitivity'];

    // Basic validation
    if (empty($service) || empty($username)) {
        die(json_encode(['success' => false, 'error' => 'Hizmet ve kullanıcı adı zorunludur']));
    }

    // Get the existing vault item
    $vaultItem = $db->select('zt_vault', ['id' => $vaultId]);
    if (empty($vaultItem)) {
        die(json_encode(['success' => false, 'error' => 'Kayıt bulunamadı']));
    }

    // Check permissions
    $vaultItem = $vaultItem[0];
    if ($role === 'intern' && $vaultItem['sensitivity'] !== 'LOW') {
        die(json_encode(['success' => false, 'error' => 'Bu işlemi yapmaya yetkiniz yok']));
    }

    if ($role === 'tech' && $vaultItem['sensitivity'] === 'CRITICAL') {
        die(json_encode(['success' => false, 'error' => 'Bu işlemi yapmaya yetkiniz yok']));
    }

    // Prepare update data
    $updateData = [
        'service' => $service,
        'username' => $username,
        'sensitivity' => $sensitivity
    ];

    // Only update password if a new one is provided
    if (!empty($newPassword)) {
        $cfg = $db->getConfig();
        $key = (string)($cfg['security']['vault']['key'] ?? 'change-me');
        $cipher = (string)($cfg['security']['vault']['cipher'] ?? 'AES-256-CBC');
        $iv = (string)($cfg['security']['vault']['iv'] ?? 'change-me-too');
        $k = hash('sha256', $key, true);
        $i = substr(hash('sha256', $iv, true), 0, 16);
        $encryptedPassword = openssl_encrypt($newPassword, $cipher, $k, 0, $i);

        if ($encryptedPassword === false) {
            die(json_encode(['success' => false, 'error' => 'Şifreleme hatası']));
        }
        $updateData['password'] = $encryptedPassword;
    }

    // Update the vault item
    $db->update('zt_vault', $updateData, ['id' => $vaultId]);

    die(json_encode(['success' => true]));
}

if ($user && isset($_GET['del_user'])) {
    if ($role === 'admin') {
        if (!SecurityHelper::verifyCsrf($_GET['csrf'] ?? null)) {
            $msg = "ENGEL: Geçersiz istek (CSRF).";
        } else {
            $du_id = $_GET['del_user'];
            $targets = $db->select('zt_users', ['id' => $du_id], 'username');
            $target = $targets[0] ?? null;

            if ($target && $target['username'] == $user) {
                $msg = "Kendini silemezsin!";
            } else {
                $db->delete('zt_users', ['id' => $du_id]);
                $msg = "Personel silindi.";
            }
        }
    } else {
        $msg = "ENGEL: Sadece admin personel silebilir!";
    }
}

$vault = [];
$users = [];

if ($user) {
    if ($role == 'intern') $vault = $db->select('zt_vault', ['sensitivity' => 'LOW']);
    elseif ($role == 'tech') $vault = $db->getConnection()->query("SELECT * FROM zt_vault WHERE sensitivity IN ('LOW', 'HIGH')")->fetchAll();
    else $vault = $db->select('zt_vault');

    if ($role == 'admin') $users = $db->select('zt_users');
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>ZT-VAULT (Secure)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light p-4">
<div class="container bg-white p-4 shadow rounded" style="max-width: 1000px;">

    <?php if (!$user): ?>
        <h3 class="text-center mb-3">ZT-VAULT GİRİŞ</h3>
        <form method="POST" class="w-50 mx-auto">
            <input type="text" name="user" class="form-control mb-2" placeholder="Kullanıcı" required>
            <input type="password" name="pass" class="form-control mb-3" placeholder="Şifre" required>
            <button type="submit" name="login" class="btn btn-primary w-100">Giriş Yap</button>
        </form>
    <?php else: ?>
        
        <div class="d-flex justify-content-between border-bottom pb-2 mb-3">
            <h4>Merhaba, <?= SecurityHelper::e($user) ?> <span class="badge bg-primary"><?= SecurityHelper::e(strtoupper((string)$role)) ?></span></h4>
            <a href="?logout" class="btn btn-danger btn-sm">Çıkış</a>
        </div>

        <?php if(isset($msg)) echo "<div class='alert alert-info py-2'>" . SecurityHelper::e($msg) . "</div>"; ?>

        <h5 class="text-secondary">Şifre Kasası</h5>
        <form method="POST" class="row g-1 mb-3">
            <input type="hidden" name="csrf" value="<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>">
            <div class="col"><input name="service" class="form-control form-control-sm" placeholder="Hizmet" required></div>
            <div class="col"><input name="login" class="form-control form-control-sm" placeholder="Kullanıcı" required></div>
            <div class="col"><input name="pass" class="form-control form-control-sm" placeholder="Şifre" required></div>
            <div class="col-2">
                <select name="sensitivity" class="form-select form-select-sm">
                    <option value="LOW">LOW</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option>
                </select>
            </div>
            <div class="col-auto"><button type="submit" name="add_vault" class="btn btn-success btn-sm">+</button></div>
        </form>

        <table class="table table-bordered table-sm mb-5">
            <thead class="table-light"><tr><th>Hizmet</th><th>Kullanıcı</th><th>Risk</th><th>İşlemler</th></tr></thead>
            <tbody>
                <?php foreach($vault as $v): ?>
                <tr>
                    <td><?= SecurityHelper::e($v['service']) ?></td>
                    <td><?= SecurityHelper::e($v['username']) ?></td>
                    <td><span class="badge <?= $v['sensitivity']=='LOW'?'bg-success':($v['sensitivity']=='HIGH'?'bg-warning':'bg-danger') ?>"><?= $v['sensitivity'] ?></span></td>
                    <td class="text-center">
                        <button type="button" class="btn btn-outline-primary btn-sm reveal-btn me-1" data-id="<?= (int)$v['id'] ?>" data-csrf="<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>">
                            Gör
                        </button>
                        <button type="button" class="btn btn-outline-warning btn-sm me-1 edit-btn" 
                                data-id="<?= (int)$v['id'] ?>" 
                                data-service="<?= SecurityHelper::e($v['service']) ?>"
                                data-username="<?= SecurityHelper::e($v['username']) ?>"
                                data-sensitivity="<?= SecurityHelper::e($v['sensitivity']) ?>"
                                data-csrf="<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>">
                            Düzenle
                        </button>
                        <a href="?del_vault=<?= $v['id'] ?>&csrf=<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>" class="btn btn-outline-danger btn-sm" onclick="return confirm('Bu kaydı silmek istediğinize emin misiniz?')">
                            Sil
                        </a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($role == 'admin'): ?>
            <div class="bg-light p-3 rounded border">
                <h5 class="text-dark">Personel Yönetimi</h5>
                <form method="POST" class="row g-1 mb-3">
                    <input type="hidden" name="csrf" value="<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>">
                    <div class="col"><input name="new_user" class="form-control form-control-sm" placeholder="Yeni Personel Adı" required></div>
                    <div class="col"><input name="new_pass" class="form-control form-control-sm" placeholder="Şifresi" required></div>
                    <div class="col">
                        <select name="new_role" class="form-select form-select-sm">
                            <option value="intern">Stajyer</option><option value="tech">Uzman</option><option value="admin">Yönetici</option>
                        </select>
                    </div>
                    <div class="col-auto"><button type="submit" name="add_user" class="btn btn-dark btn-sm">Ekle</button></div>
                </form>

                <table class="table table-sm bg-white">
                    <thead><tr><th>ID</th><th>Kullanıcı</th><th>Rol</th><th>İşlemler</th></tr></thead>
                    <tbody>
                        <?php foreach($users as $u): 
                            $isCurrentUser = ($u['username'] === ($_SESSION['user'] ?? ''));
                        ?>
                        <tr>
                            <td><?= $u['id'] ?></td>
                            <td><?= SecurityHelper::e($u['username']) ?></td>
                            <td>
                                <span class="badge bg-secondary text-dark user-select-none" data-user-id="<?= $u['id'] ?>" style="cursor: pointer; min-width: 80px; display: inline-block; text-align: center;">
                                    <?= SecurityHelper::e($u['role']) ?>
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
                                        data-username="<?= SecurityHelper::e($u['username']) ?>"
                                        data-role="<?= SecurityHelper::e($u['role']) ?>">
                                    Düzenle
                                </button>
                                <?php if (!$isCurrentUser): ?>
                                <a href="?del_user=<?= $u['id'] ?>&csrf=<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>" 
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
                                <input type="hidden" name="csrf" value="<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>">
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
                        
                        // Update role via AJAX
                        const formData = new FormData();
                        formData.append('csrf', '<?= SecurityHelper::e(SecurityHelper::csrfToken()) ?>');
                        formData.append('update_user', '1');
                        formData.append('user_id', userId);
                        formData.append('edit_role', newRole);
                        
                        fetch(window.location.href, {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.text())
                        .then(() => {
                            // Update UI
                            const badge = document.querySelector(`[data-user-id="${userId}"]`);
                            badge.textContent = newRole;
                            this.classList.add('d-none');
                            badge.classList.remove('d-none');
                            
                            // Update button data attribute if it's the current user
                            const editButton = document.querySelector(`.edit-user[data-id="${userId}"]`);
                            if (editButton) {
                                editButton.dataset.role = newRole;
                            }
                            
                            // Reload the page to reflect changes
                            window.location.reload();
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            alert('Rol güncellenirken bir hata oluştu.');
                        });
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
                
            </div>
        <?php endif; ?>

        <div class="modal fade" id="passwordModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Şifre</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <div class="modal-body">
                        <div class="input-group mb-3">
                            <input type="text" id="revealedPassword" class="form-control" readonly>
                            <button class="btn btn-outline-secondary" type="button" id="copyPasswordBtn">
                                Kopyala
                            </button>
                        </div>
                        <div id="passwordError" class="text-danger small"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Edit Vault Modal -->
        <div class="modal fade" id="editVaultModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Şifreyi Güncelle</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                    </div>
                    <form id="editVaultForm" method="POST">
                        <input type="hidden" name="csrf" id="editVaultCsrf">
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
                                <label class="form-label">Yeni Şifre</label>
                                <input type="text" class="form-control" name="new_password" id="editPassword" required>
                                <div class="form-text">Boş bırakılırsa mevcut şifre korunur.</div>
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

    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<?php if ($user): ?>
<script>
(function () {
    var idleMs = 60 * 1000;
    var countdownSeconds = 30;
    var timerId = null;
    var countdownId = null;
    var remaining = countdownSeconds;

    var modalEl = document.getElementById('presenceModal');
    var countdownEl = document.getElementById('presenceCountdown');
    var stayBtn = document.getElementById('presenceStayBtn');
    var logoutBtn = document.getElementById('presenceLogoutBtn');
    var modal = new bootstrap.Modal(modalEl, {backdrop: 'static', keyboard: false});

    function resetIdleTimer() {
        if (timerId) clearTimeout(timerId);
        timerId = setTimeout(showModal, idleMs);
    }

    function stopCountdown() {
        if (countdownId) clearInterval(countdownId);
        countdownId = null;
    }

    function showModal() {
        remaining = countdownSeconds;
        countdownEl.textContent = String(remaining);
        modal.show();
        stopCountdown();
        countdownId = setInterval(function () {
            remaining -= 1;
            countdownEl.textContent = String(remaining);
            if (remaining <= 0) {
                stopCountdown();
                window.location.href = '?logout=1';
            }
        }, 1000);
    }

    function stay() {
        axios.get('?ping=1', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store'
        }).finally(function () {
            stopCountdown();
            modal.hide();
            resetIdleTimer();
        });
    }

    function logout() {
        window.location.href = '?logout=1';
    }

    var passwordModalEl = document.getElementById('passwordModal');
    var passwordModal = new bootstrap.Modal(passwordModalEl);
    var revealedEl = document.getElementById('revealedPassword');
    var errorEl = document.getElementById('passwordError');

    function setPasswordModal(password, error) {
        revealedEl.value = password || '';
        errorEl.textContent = error || '';
    }

    function revealPassword(btn) {
        var id = btn.getAttribute('data-id');
        var csrf = btn.getAttribute('data-csrf');
        setPasswordModal('', '');
        passwordModal.show();
        axios.get('?reveal_vault=' + encodeURIComponent(id) + '&csrf=' + encodeURIComponent(csrf), {cache: 'no-store'})
            .then(function (resp) {
                if (resp.data && resp.data.ok) {
                    setPasswordModal(String(resp.data.password || ''), '');
                } else {
                    setPasswordModal('', 'Şifre alınamadı');
                }
            })
            .catch(function () {
                setPasswordModal('', 'Şifre alınamadı');
            });
    }

    document.getElementById('copyPasswordBtn')?.addEventListener('click', function() {
        revealedEl.select();
        document.execCommand('copy');
        this.innerHTML = 'Kopyalandı!';
        setTimeout(() => {
            this.innerHTML = 'Kopyala';
        }, 2000);
    });

    document.addEventListener('click', function(e) {
        if (e.target.closest('.reveal-btn')) {
            revealPassword(e.target.closest('.reveal-btn'));
        }
        
        // Handle edit button click
        const editBtn = e.target.closest('.edit-btn');
        if (editBtn) {
            const id = editBtn.dataset.id;
            const service = editBtn.dataset.service;
            const username = editBtn.dataset.username;
            const sensitivity = editBtn.dataset.sensitivity;
            const csrf = editBtn.dataset.csrf;
            
            // Show loading state
            const editModal = document.getElementById('editVaultModal');
            const modalTitle = editModal.querySelector('.modal-title');
            const originalTitle = modalTitle.textContent;
            modalTitle.textContent = 'Yükleniyor...';
            
            // Get current password
            axios.get('?reveal_vault=' + encodeURIComponent(id) + '&csrf=' + encodeURIComponent(csrf), {cache: 'no-store'})
                .then(function (resp) {
                    if (resp.data && resp.data.ok) {
                        const currentPassword = resp.data.password || '';
                        
                        // Update form fields
                        document.getElementById('editVaultId').value = id;
                        document.getElementById('editService').value = service;
                        document.getElementById('editUsername').value = username;
                        document.getElementById('editPassword').value = currentPassword;
                        document.getElementById('editSensitivity').value = sensitivity;
                        document.getElementById('editVaultCsrf').value = csrf;
                        
                        // Restore title and show modal
                        modalTitle.textContent = originalTitle;
                        const modal = new bootstrap.Modal(editModal);
                        modal.show();
                    } else {
                        setPasswordModal('', 'Şifre alınamadı');
                    }
                })
                .catch(function () {
                    setPasswordModal('', 'Şifre alınamadı');
                });
        }
    });

    // Handle edit form submission
    document.getElementById('editVaultForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);
        
        axios.post('?update_vault=1', formData)
            .then(response => {
                if (response.data && response.data.success) {
                    location.reload();
                } else {
                    alert('Güncelleme başarısız: ' + (response.data?.error || 'Bilinmeyen hata'));
                }
            })
            .catch(error => {
                alert('Bir hata oluştu: ' + (error.response?.data?.error || error.message));
            });
    });

    resetIdleTimer();
})();
</script>
<?php endif; ?>
</body>
</html>