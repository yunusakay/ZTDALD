<?php
session_start();
require '../config.php';
require '../BaseVaultManager.php';

class ZTVaultManager extends BaseVaultManager {
    protected function getTitle() {
        return 'ZT Vault';
    }
<<<<<<< HEAD
    
    protected function getTemplate($data) {
        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="UTF-8">
            <title>ZT VAULT</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light p-4">
        <div class="container bg-white p-4 shadow rounded" style="max-width: 900px;">
            <?php if (!$this->user): ?>
                <?= $this->renderLoginForm() ?>
            <?php else: ?>
                <?= $this->renderHeader() ?>
                <?= $this->showMessage() ?>
                <?= $this->renderVaultForm($data['vault']) ?>
                <?= $this->renderUserForm($data['users']) ?>
            <?php endif; ?>
=======
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
                'type' => 'password',
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
        'new_password' => [
            'type' => 'password',
            'required' => false,
            'min_length' => 4,
            'message' => 'Yeni şifre en az 4 karakter olmalıdır'
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
>>>>>>> 943124a4f1928fc90fad812b12536a6758a4e0d6
        </div>
        <?= $this->renderModals() ?>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <?= $this->renderScripts() ?>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }
    
    protected function renderVaultForm($vault) {
        ob_start();
        ?>
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
                    <td><?= $this->getSensitivityBadge($v['sensitivity']) ?></td>
                    <td>
                        <?php 
                        // Check if current user matches the vault username or is admin
                        $canViewPassword = ($this->user === $v['username']) || ($this->role === 'admin');
                        if ($canViewPassword) {
                            echo htmlspecialchars($v['password']);
                        } else {
                            echo '••••••••';
                        }
                        ?>
                    </td>
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
        <?php
        return ob_get_clean();
    }
    
    protected function renderScripts() {
        ob_start();
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.edit-user').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.getElementById('editUserId').value = this.dataset.id;
                    document.getElementById('editUsername').value = this.dataset.username;
                    document.getElementById('editPassword').value = '';
                    new bootstrap.Modal(document.getElementById('editUserModal')).show();
                });
            });
            
            document.addEventListener('click', function(e) {
                const btn = e.target.closest('.edit-btn');
                if (btn) {
                    document.getElementById('editVaultId').value = btn.dataset.id;
                    document.getElementById('editService').value = btn.dataset.service;
                    document.getElementById('editUsername').value = btn.dataset.username;
                    document.getElementById('editPassword').value = btn.dataset.password;
                    document.getElementById('editSensitivity').value = btn.dataset.sensitivity;
                    new bootstrap.Modal(document.getElementById('editVaultModal')).show();
                }
            });
        });
        </script>
        <?php
        return ob_get_clean();
    }
}

$vault = new ZTVaultManager($pdo, 'zt');
$vault->login();
$vault->logout();
$vault->handleOperations();
$vault->render();
?>
