<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>ZT-VAULT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    
    <style>
        /* Sadece özel yerleşim için minik CSS (Bootstrap yetmediği yerde) */
        body { background-color: #f8f9fa; } /* Açık Gri Arka Plan */
        .toast-container { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); z-index: 1050; }
        .font-mono { font-family: 'Courier New', monospace; letter-spacing: 1px; }
    </style>
</head>
<body>

<div x-data="vaultApp()">

    <template x-if="!token">
        <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="card shadow-sm border-0 p-4" style="width: 100%; max-width: 350px;">
                <h3 class="fw-bold text-dark mb-1">Giriş Yap</h3>
                <p class="text-muted small mb-4">Kurumsal Erişim Kasası</p>
                
                <div class="mb-3">
                    <input x-model="user" type="text" class="form-control" placeholder="Kullanıcı Adı">
                </div>
                <div class="mb-3">
                    <input x-model="pass" type="password" class="form-control" placeholder="Şifre">
                </div>
                <button @click="login" class="btn btn-primary w-100 fw-bold">Bağlan</button>
            </div>
        </div>
    </template>

    <template x-if="token">
        <div class="container py-5" style="max-width: 1000px;">
            
            <div class="d-flex justify-content-between align-items-center mb-4 border-bottom pb-3">
                <h4 class="fw-bold text-primary m-0">ZT-VAULT</h4>
                <div class="d-flex align-items-center gap-3">
                    <span class="badge bg-light text-dark border px-3 py-2">
                        <span x-text="currentUser"></span> 
                        <span class="text-muted mx-1">|</span> 
                        <span class="fw-bold text-primary" x-text="currentRole.toUpperCase()"></span>
                    </span>
                    <button @click="logout" class="btn btn-sm btn-outline-danger">Çıkış</button>
                </div>
            </div>

            <div class="card shadow-sm border-0 overflow-hidden">
                <table class="table table-hover align-middle mb-0">
                    <thead class="table-light">
                        <tr class="text-uppercase small text-muted">
                            <th class="ps-4 py-3">Hizmet Adı</th>
                            <th>Kullanıcı ID</th>
                            <th>Hassasiyet</th>
                            <th class="text-end pe-4">Erişim Anahtarı</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="item in items" :key="item.id">
                            <tr>
                                <td class="ps-4 fw-bold text-dark" x-text="item.service_name"></td>
                                <td class="font-mono text-muted" x-text="item.username_login"></td>
                                <td>
                                    <span class="badge rounded-pill" 
                                          :class="{
                                              'bg-success': item.sensitivity === 'LOW',
                                              'bg-warning text-dark': item.sensitivity === 'HIGH',
                                              'bg-danger': item.sensitivity === 'CRITICAL'
                                          }" 
                                          x-text="item.sensitivity">
                                    </span>
                                </td>
                                <td class="text-end pe-4">
                                    <div class="d-flex justify-content-end align-items-center gap-2">
                                        <span class="font-mono bg-light px-2 py-1 rounded border" 
                                              :class="{'text-primary fw-bold': item.revealed, 'text-muted': !item.revealed}"
                                              x-text="item.revealed ? item.real_password : '••••••••••••'">
                                        </span>
                                        <button @click="reveal(item)" class="btn btn-sm btn-outline-secondary" 
                                                x-text="item.revealed ? 'Gizle' : 'Göster'"></button>
                                    </div>
                                </td>
                            </tr>
                        </template>

                        <tr x-show="items.length === 0">
                            <td colspan="4" class="text-center py-5 text-muted">
                                Görüntülenecek veri bulunamadı.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="text-center mt-3 text-muted small">
                AES-256 Şifreleme • Zero Trust Protokolü
            </div>

        </div>
    </template>

    <div x-show="toastVisible" class="toast-container" style="display: none;">
        <div class="alert shadow-lg fw-bold px-4" 
             :class="toastType === 'error' ? 'alert-danger' : 'alert-success'"
             x-text="toastMsg">
        </div>
    </div>

</div>

<script>
    function vaultApp() {
        return {
            token: localStorage.getItem('vault_token'),
            currentUser: localStorage.getItem('vault_user'),
            currentRole: localStorage.getItem('vault_role'),
            user: '', pass: '', items: [],
            toastVisible: false, toastMsg: '', toastType: '',

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
                        
                        localStorage.setItem('vault_token', this.token);
                        localStorage.setItem('vault_user', this.currentUser);
                        localStorage.setItem('vault_role', this.currentRole);
                        
                        axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
                        this.loadVault();
                    } else this.notify('Giriş Başarısız', 'error');
                } catch(e) { this.notify('Hata oluştu', 'error'); }
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
                    this.notify('Şifre Çözüldü', 'success');
                } catch(e) {
                    const msg = e.response && e.response.data.message ? e.response.data.message : 'Yetkisiz Erişim!';
                    this.notify(msg, 'error');
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