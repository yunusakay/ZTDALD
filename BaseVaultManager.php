<?php

abstract class BaseVaultManager {
    protected $pdo;
    protected $user;
    protected $role;
    public $msg;
    protected $prefix;
    
    public function __construct($pdo, $prefix) {
        $this->pdo = $pdo;
        $this->prefix = $prefix;
        $this->user = $_SESSION['user'] ?? null;
        $this->role = $_SESSION['role'] ?? null;
    }
    
    protected function validateInput($field, $min = 1, $max = 50) {
        return !empty(trim($field)) && strlen(trim($field)) >= $min && strlen(trim($field)) <= $max;
    }
    
    protected function showMessage() {
        return isset($this->msg) ? "<div class='alert alert-light border mb-4'>{$this->msg}</div>" : '';
    }
    
    protected function getUserBadge($role) {
        return "<span class='badge bg-secondary text-dark' style='min-width: 80px; display: inline-block; text-align: center;'>" . htmlspecialchars($role) . "</span>";
    }
    
    protected function getSensitivityBadge($level) {
        $colors = ['LOW' => 'bg-success', 'HIGH' => 'bg-warning', 'CRITICAL' => 'bg-danger'];
        return "<span class='badge {$colors[$level]}'>{$level}</span>";
    }
    
    public function login() {
        if (isset($_POST['login'])) {
            $username = $_POST['user'] ?? '';
            $password = $_POST['pass'] ?? '';
            
            // First try plain text (for L database)
            $stmt = $this->pdo->prepare("SELECT * FROM {$this->prefix}_users WHERE username = ? AND password = ?");
            $stmt->execute([$username, $password]);
            $user = $stmt->fetch();
            
            if ($user) {
                $_SESSION['user'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $this->user = $user['username'];
                $this->role = $user['role'];
            } else {
                // Try hashed password (for ZT database)
                $stmt = $this->pdo->prepare("SELECT * FROM {$this->prefix}_users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password'])) {
                    $_SESSION['user'] = $user['username'];
                    $_SESSION['role'] = $user['role'];
                    $this->user = $user['username'];
                    $this->role = $user['role'];
                }
            }
        }
    }
    
    public function logout() {
        if (isset($_GET['logout'])) {
            session_destroy();
            header("Location: index.php");
            exit;
        }
    }
    
    public function handleOperations() {
        if (!$this->user || $this->role !== 'admin') return;
        
        if (isset($_POST['add_vault'])) $this->addVault($_POST);
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_vault'])) $this->updateVault($_POST);
        if (isset($_GET['del_vault'])) $this->deleteVault((int)$_GET['del_vault']);
        if (isset($_POST['add_user'])) $this->addUser($_POST);
        if (isset($_POST['update_user'])) $this->updateUser($_POST);
        if (isset($_GET['del_user'])) $this->deleteUser((int)$_GET['del_user']);
    }
    
    protected function addVault($data) {
        try {
            $stmt = $this->pdo->prepare("INSERT INTO {$this->prefix}_vault (service, username, password, sensitivity) VALUES (?, ?, ?, ?)");
            $stmt->execute([$data['service'], $data['login'], $data['pass'], $data['sensitivity']]);
            $this->msg = "Kayıt Başarılı.";
        } catch (PDOException $e) {
            $this->msg = "Veritabanı hatası: " . $e->getMessage();
        }
    }
    
    protected function updateVault($data) {
        try {
            $stmt = $this->pdo->prepare("UPDATE {$this->prefix}_vault SET service = ?, username = ?, password = ?, sensitivity = ? WHERE id = ?");
            $stmt->execute([$data['service'], $data['username'], $data['password'], $data['sensitivity'], $data['vault_id']]);
            $this->msg = "Kasa kaydı güncellendi.";
        } catch (PDOException $e) {
            $this->msg = "Veritabanı hatası: " . $e->getMessage();
        }
    }
    
    protected function deleteVault($id) {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM {$this->prefix}_vault WHERE id = ?");
            $stmt->execute([$id]);
            $this->msg = "Kasa kaydı silindi.";
        } catch (PDOException $e) {
            $this->msg = "Veritabanı hatası: " . $e->getMessage();
        }
    }
    
    protected function addUser($data) {
        $nu = trim($data['new_user'] ?? '');
        $np = $data['new_pass'] ?? '';
        $nr = $data['new_role'] ?? 'intern';
        
        if (!$this->validateInput($nu, 3) || !$this->validateInput($np, 4)) {
            $this->msg = "Kullanıcı adı ve şifre zorunludur! (Şifre en az 4 karakter)";
        } elseif (!in_array($nr, ['admin', 'tech', 'intern'])) {
            $this->msg = "Geçersiz rol seçildi!";
        } else {
            try {
                $stmt = $this->pdo->prepare("SELECT id FROM {$this->prefix}_users WHERE username = ?");
                $stmt->execute([$nu]);
                if ($stmt->fetch()) {
                    $this->msg = "Bu kullanıcı adı zaten kullanılıyor!";
                } else {
                    $stmt = $this->pdo->prepare("INSERT INTO {$this->prefix}_users (username, password, role) VALUES (?, ?, ?)");
                    $stmt->execute([$nu, $np, $nr]);
                    $this->msg = "Personel eklendi.";
                }
            } catch (PDOException $e) {
                $this->msg = "Veritabanı hatası: " . $e->getMessage();
            }
        }
    }
    
    protected function updateUser($data) {
        $stmt = $this->pdo->prepare("SELECT * FROM {$this->prefix}_users WHERE id = ?");
        $stmt->execute([$data['user_id']]);
        $existing = $stmt->fetch();
        
        if (!$existing) {
            $this->msg = "Kullanıcı bulunamadı.";
            return;
        }
        
        $nu = trim($data['edit_username'] ?? '');
        $nr = $data['edit_role'] ?? 'intern';
        $np = $data['edit_password'] ?? '';
        
        if (!$this->validateInput($nu, 3) || !in_array($nr, ['admin', 'tech', 'intern'])) {
            $this->msg = "Geçersiz kullanıcı bilgileri.";
            return;
        }
        
        try {
            $params = [$nu, $nr, $data['user_id']];
            $sql = "UPDATE {$this->prefix}_users SET username = ?, role = ?";
            
            if (!empty($np) && strlen($np) >= 4) {
                $sql .= ", password = ?";
                $params = [$nu, $nr, $np, $data['user_id']];
            }
            
            $sql .= " WHERE id = ?";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            $this->msg = "Kullanıcı bilgileri güncellendi.";
            
            if ($data['user_id'] === $_SESSION['user_id']) {
                $_SESSION['user'] = $nu;
                $_SESSION['role'] = $nr;
            }
        } catch (PDOException $e) {
            $this->msg = "Veritabanı hatası: " . $e->getMessage();
        }
    }
    
    protected function deleteUser($id) {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM {$this->prefix}_users WHERE id = ?");
            $stmt->execute([$id]);
            $this->msg = "Personel Silindi.";
        } catch (PDOException $e) {
            $this->msg = "Veritabanı hatası: " . $e->getMessage();
        }
    }
    
    protected function loadData() {
        if (!$this->user) return [];
        
        try {
            return [
                'vault' => $this->pdo->query("SELECT * FROM {$this->prefix}_vault")->fetchAll(),
                'users' => $this->pdo->query("SELECT * FROM {$this->prefix}_users")->fetchAll()
            ];
        } catch (Exception $e) {
            $this->msg = "Veri yükleme hatası: " . $e->getMessage();
            return [];
        }
    }
    
    abstract protected function getTemplate($data);
    abstract protected function getTitle();
    
    public function render() {
        $data = $this->loadData();
        if (!is_array($data)) {
            $data = ['vault' => [], 'users' => []];
        }
        echo $this->getTemplate($data);
    }
    
    protected function renderLoginForm() {
        return '
            <h4 class="text-center mb-4">Giriş Yap</h4>
            <form method="POST" class="w-50 mx-auto">
                <input type="text" name="user" class="form-control mb-2" placeholder="Kullanıcı Adı">
                <input type="password" name="pass" class="form-control mb-3" placeholder="Şifre">
                <button type="submit" name="login" class="btn btn-dark w-100">Giriş</button>
            </form>';
    }
    
    protected function renderHeader() {
        return '
            <div class="d-flex justify-content-between border-bottom pb-3 mb-4">
                <h4 class="m-0">' . $this->getTitle() . ' <span class="badge bg-secondary fs-6">' . strtoupper($this->role) . '</span></h4>
                <a href="?logout" class="btn btn-outline-danger btn-sm">Çıkış</a>
            </div>';
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
        <?php
        return ob_get_clean();
    }
    
    protected function renderUserForm($users) {
        ob_start();
        ?>
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
                <thead><tr><th>ID</th><th>Kullanıcı</th><th>Rol</th><th>İşlemler</th></tr></thead>
                <tbody>
                    <?php foreach($users as $u): 
                        $isCurrentUser = ($u['username'] === ($_SESSION['user'] ?? ''));
                    ?>
                    <tr>
                        <td><?= htmlspecialchars($u['id']) ?></td>
                        <td><?= htmlspecialchars($u['username']) ?></td>
                        <td><?= $this->getUserBadge($u['role']) ?></td>
                        <td class="d-flex gap-1">
                            <button type="button" class="btn btn-sm btn-outline-primary edit-user" 
                                    data-id="<?= $u['id'] ?>"
                                    data-username="<?= htmlspecialchars($u['username']) ?>">
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
        </div>
        <?php
        return ob_get_clean();
    }
    
    protected function renderModals() {
        ob_start();
        ?>
        <div class="modal fade" id="editUserModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Kullanıcı Düzenle</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <form method="POST" id="editUserForm">
                        <input type="hidden" name="update_user" value="1">
                        <input type="hidden" name="user_id" id="editUserId">
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label">Kullanıcı Adı</label>
                                <input type="text" class="form-control" id="editUsername" name="edit_username" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Rol</label>
                                <select class="form-select" id="editRole" name="edit_role" required>
                                    <option value="admin">Yönetici</option><option value="tech">Uzman</option><option value="intern">Stajyer</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Yeni Şifre (Değiştirmek istemiyorsanız boş bırakın)</label>
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
?>
