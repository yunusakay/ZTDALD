<?php
session_start();
require '../config.php';
require '../BaseVaultManager.php';

class LVaultManager extends BaseVaultManager {
    protected function getTitle() {
        return 'Kurumsal Kasa';
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
    
    protected function getTemplate($data) {
        ob_start();
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
            <?php if (!$this->user): ?>
                <?= $this->renderLoginForm() ?>
            <?php else: ?>
                <?= $this->renderHeader() ?>
                <?= $this->showMessage() ?>
                <?= $this->renderVaultForm($data['vault']) ?>
                <?= $this->renderUserForm($data['users']) ?>
            <?php endif; ?>
        </div>
        <?= $this->renderModals() ?>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <?= $this->renderScripts() ?>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }
}

$vault = new LVaultManager($pdo, 'l');
$vault->login();
$vault->logout();
$vault->handleOperations();
$vault->render();
?>
