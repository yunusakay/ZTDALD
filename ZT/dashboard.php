<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>ZT-VAULT | Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body { background-color: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; }
        .font-mono { font-family: 'Courier New', monospace; letter-spacing: 0.5px; }
        .toast-container { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); z-index: 1050; }
        .table-hover tbody tr:hover { background-color: #f1f3f5; }
    </style>
</head>
<body>

<div x-data="vaultApp()">

    <template x-if="!token">
        <div class="d-flex justify-content-center align-items-center vh-100">
            <div class="card shadow border-0 p-4" style="width: 350px;">
                <h4 class="fw-bold mb-3 text-primary">ZT-VAULT Admin</h4>
                <input x-model="user" class="form-control mb-2" placeholder="Kullanıcı Adı">
                <input x-model="pass" type="password" class="form-control mb-3" placeholder="Şifre">
                <button @click="login" class="btn btn-primary w-100 fw-bold">Yönetim Paneline Gir</button>
            </div>
        </div>
    </template>

    <template x-if="token">
        <div class="container py-5" style="max-width: 1200px;">
            
            <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom">
                <div>
                    <h3 class="fw-bold m-0 text-dark">Kurumsal Şifre Kasası</h3>
                    <small class="text-muted">Zero Trust Yönetim Merkezi</small>
                </div>
                <div class="d-flex gap-2">
                    <button class="btn btn-success fw-bold px-4" data-bs-toggle="modal" data-bs-target="#addModal">+ Yeni Kayıt</button>
                    <button @click="logout" class="btn btn-outline-danger">Oturumu Kapat</button>
                </div>
            </div>

            <div class="alert alert-light border shadow-sm d-flex justify-content-between align-items-center py-2 px-3 mb-4">
                <span>Giriş Yapan: <b><span x-text="currentUser"></span></b></span>
                <span class="badge bg-secondary" x-text="'ROL: ' + currentRole.toUpperCase()"></span>
            </div>

            <div class="card shadow-sm border-0 overflow-hidden">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr class="text-secondary small text-uppercase">
                            <th class="ps-4">Hizmet Adı</th>
                            <th>Kullanıcı ID</th>
                            <th>Hassasiyet</th>
                            <th>Onaylayan</th>
                            <th class="text-end">Erişim</th>
                            <th class="text-end pe-4">İşlemler</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="item in items" :key="item.id">
                            <tr>
                                <td class="ps-4 fw-bold text-dark" x-text="item.service_name"></td>
                                <td class="font-mono text-muted small" x-text="item.username_login"></td>
                                
                                <td>
                                    <span class="badge rounded-pill" 
                                          :class="{
                                              'bg-success': item.sensitivity === 'LOW',
                                              'bg-warning text-dark': item.sensitivity === 'HIGH',
                                              'bg-danger': item.sensitivity === 'CRITICAL'
                                          }" x-text="item.sensitivity"></span>
                                </td>

                                <td class="text-muted small" x-text="item.decided_by"></td>

                                <td class="text-end">
                                    <div class="d-flex justify-content-end gap-2">
                                        <span class="font-mono bg-light border px-2 rounded small d-flex align-items-center" 
                                              style="min-width: 100px; height: 30px;"
                                              :class="{'text-primary fw-bold': item.revealed}"
                                              x-text="item.revealed ? item.real_password : '••••••••'"></span>
                                        <button @click="reveal(item)" class="btn btn-sm btn-outline-secondary" x-text="item.revealed ? 'Gizle' : 'Aç'"></button>
                                    </div>
                                </td>

                                <td class="text-end pe-4">
                                    <div class="btn-group">
                                        <button @click="openEditModal(item)" class="btn btn-sm btn-outline-primary">Düzenle</button>
                                        <button @click="deleteItem(item)" class="btn btn-sm btn-outline-danger">Sil</button>
                                    </div>
                                </td>
                            </tr>
                        </template>
                        <tr x-show="items.length === 0"><td colspan="6" class="text-center py-5 text-muted">Kayıt bulunamadı.</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div class="text-center mt-3 text-muted small">
                🔒 Tüm işlemler loglanmaktadır. Yetkisiz değişiklik girişimi engellenir.
            </div>

        </div>
    </template>

    <div class="modal fade" id="addModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title fw-bold">Yeni Kayıt Ekle</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label small text-muted">Hizmet Adı</label>
                        <input x-model="newItem.service" class="form-control" placeholder="Örn: Azure Portal">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small text-muted">Giriş Kullanıcısı</label>
                        <input x-model="newItem.login" class="form-control" placeholder="Örn: admin@azure">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small text-muted">Şifre</label>
                        <input x-model="newItem.pass" type="text" class="form-control" placeholder="Güvenli şifre girin">
                    </div>
                    <div class="row">
                        <div class="col-6 mb-3">
                            <label class="form-label small text-muted">Hassasiyet</label>
                            <select x-model="newItem.sensitivity" class="form-select">
                                <option value="LOW">LOW</option>
                                <option value="HIGH">HIGH</option>
                                <option value="CRITICAL">CRITICAL</option>
                            </select>
                        </div>
                        <div class="col-6 mb-3">
                            <label class="form-label small text-muted">Onaylayan</label>
                            <input x-model="newItem.decided_by" class="form-control" placeholder="Örn: CTO">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-light" data-bs-dismiss="modal">İptal</button>
                    <button @click="addItem" type="button" class="btn btn-success" data-bs-dismiss="modal">Kaydet</button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="editModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title fw-bold">Kaydı Düzenle</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label small text-muted">Hizmet Adı</label>
                        <input x-model="editItemData.service" class="form-control">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small text-muted">Giriş Kullanıcısı</label>
                        <input x-model="editItemData.login" class="form-control">
                    </div>
                    <div class="mb-3">
                        <label class="form-label small text-muted">Şifre (Değiştirmek için yazın, yoksa boş bırakın)</label>
                        <input x-model="editItemData.pass" type="text" class="form-control" placeholder="••••••">
                    </div>
                    <div class="row">
                        <div class="col-6 mb-3">
                            <label class="form-label small text-muted">Hassasiyet</label>
                            <select x-model="editItemData.sensitivity" class="form-select">
                                <option value="LOW">LOW</option>
                                <option value="HIGH">HIGH</option>
                                <option value="CRITICAL">CRITICAL</option>
                            </select>
                        </div>
                        <div class="col-6 mb-3">
                            <label class="form-label small text-muted">Onaylayan</label>
                            <input x-model="editItemData.decided_by" class="form-control">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-light" data-bs-dismiss="modal">İptal</button>
                    <button @click="updateItem" type="button" class="btn btn-primary" data-bs-dismiss="modal">Güncelle</button>
                </div>
            </div>
        </div>
    </div>

    <div x-show="toastVisible" class="toast-container">
        <div class="alert shadow-lg fw-bold px-4 py-2 border-0" 
             :class="toastType==='error'?'alert-danger text-danger':'alert-success text-success'" 
             x-text="toastMsg"></div>
    </div>

</div>

<script>
    // Edit Modal için Bootstrap instance
    let editModalInstance = null;

    function vaultApp() {
        return {
            token: localStorage.getItem('vt_token'),
            currentUser: localStorage.getItem('vt_user'),
            currentRole: localStorage.getItem('vt_role'),
            user: '', pass: '', items: [],
            toastVisible: false, toastMsg: '', toastType: '',
            
            newItem: { service: '', login: '', pass: '', sensitivity: 'LOW', decided_by: '' },
            editItemData: { id: null, service: '', login: '', pass: '', sensitivity: '', decided_by: '' },

            init() {
                if(this.token) {
                    axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
                    this.loadVault();
                }
            },

            async login() {
                try {
                    const r = await axios.post('api.php?action=login', {username:this.user, password:this.pass});
                    if(r.data.status === 'success') {
                        this.token = r.data.token;
                        this.currentUser = this.user;
                        this.currentRole = r.data.role;
                        localStorage.setItem('vt_token', this.token);
                        localStorage.setItem('vt_user', this.currentUser);
                        localStorage.setItem('vt_role', this.currentRole);
                        axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
                        this.loadVault();
                    } else this.notify('Giriş Başarısız', 'error');
                } catch(e) { this.notify('Hata', 'error'); }
            },

            logout() { localStorage.clear(); location.reload(); },

            async loadVault() {
                try {
                    const r = await axios.get('api.php?action=get_vault');
                    this.items = r.data.data.map(i => ({...i, revealed: false, real_password: ''}));
                } catch(e) {}
            },

            async reveal(item) {
                if(item.revealed) { item.revealed = false; return; }
                try {
                    const r = await axios.post('api.php?action=reveal', {id: item.id});
                    item.real_password = r.data.password;
                    item.revealed = true;
                } catch(e) { this.notify(e.response.data.message || 'Yetkisiz!', 'error'); }
            },

            // EKLEME
            async addItem() {
                try {
                    await axios.post('api.php?action=add', this.newItem);
                    this.notify('Başarıyla Eklendi', 'success');
                    this.loadVault();
                    this.newItem = { service: '', login: '', pass: '', sensitivity: 'LOW', decided_by: '' };
                } catch(e) { this.notify(e.response.data.message || 'Hata', 'error'); }
            },

            // SİLME
            async deleteItem(item) {
                if(!confirm('Silmek istediğine emin misin?')) return;
                try {
                    await axios.post('api.php?action=delete', {id: item.id});
                    this.notify('Silindi', 'success');
                    this.loadVault();
                } catch(e) { this.notify(e.response.data.message || 'Yetkisiz İşlem!', 'error'); }
            },

            // DÜZENLEME (MODAL AÇMA)
            openEditModal(item) {
                this.editItemData = {
                    id: item.id,
                    service: item.service_name,
                    login: item.username_login,
                    pass: '', // Şifre güvenliği için boş gelir, isterse değiştirir
                    sensitivity: item.sensitivity,
                    decided_by: item.decided_by
                };
                // Bootstrap modalını JS ile aç
                if(!editModalInstance) editModalInstance = new bootstrap.Modal(document.getElementById('editModal'));
                editModalInstance.show();
            },

            // GÜNCELLEME (SAVE)
            async updateItem() {
                try {
                    await axios.post('api.php?action=update', this.editItemData);
                    this.notify('Güncelleme Başarılı', 'success');
                    this.loadVault();
                } catch(e) {
                    this.notify(e.response.data.message || 'Güncelleme Yetkiniz Yok!', 'error');
                }
            },

            notify(msg, type) {
                this.toastMsg = msg;
                this.toastType = type;
                this.toastVisible = true;
                setTimeout(() => this.toastVisible = false, 3000);
            }
        }
    }
</script>
</body>
</html>