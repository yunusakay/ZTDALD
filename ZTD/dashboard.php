<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero Trust Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
</head>
<body class="bg-light">

<div x-data="ztApp()" x-init="init()" class="container mt-5">

    <template x-if="!token">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card shadow border-0">
                    <div class="card-body p-4">
                        <h4 class="text-center mb-4">Giriş Yap</h4>
                        <form @submit.prevent="login">
                            <div class="mb-3">
                                <label>Kullanıcı Adı</label>
                                <input x-model="form.username" type="text" class="form-control" placeholder="analyst">
                            </div>
                            <div class="mb-3">
                                <label>Şifre</label>
                                <input x-model="form.password" type="password" class="form-control" placeholder="pass123">
                            </div>
                            <button type="submit" class="btn btn-primary w-100" :disabled="loading">
                                <span x-text="loading ? 'Giriş Yapılıyor...' : 'Giriş Yap'"></span>
                            </button>
                        </form>
                        <div x-show="error" x-text="error" class="alert alert-danger mt-3 text-center py-2"></div>
                    </div>
                </div>
            </div>
        </div>
    </template>

    <template x-if="token">
        <div>
            <nav class="navbar navbar-dark bg-dark rounded px-3 mb-4 d-flex justify-content-between">
                <span class="navbar-brand h1 m-0">Zero Trust Demo</span>
                <button @click="logout" class="btn btn-outline-light btn-sm">Çıkış</button>
            </nav>

            <div class="text-center">
                <h3>Hoşgeldin, <span class="text-primary" x-text="form.username || 'Kullanıcı'"></span></h3>
                <p class="text-muted">Mevcut Rolün: <strong x-text="role"></strong></p>
            </div>

            <div class="row justify-content-center mt-4">
                <div class="col-md-8 text-center">
                    <div class="card shadow-sm">
                        <div class="card-header bg-white">İşlemler</div>
                        <div class="card-body">
                            <div class="mb-3">
                                <button @click="req('view')" class="btn btn-success m-1">Görüntüle (Herkes)</button>
                                <button @click="req('edit')" class="btn btn-warning m-1">Düzenle (Editör)</button>
                                <button @click="req('admin')" class="btn btn-danger m-1">Admin (Yasak)</button>
                            </div>

                            <div x-show="apiResult" class="mt-3">
                                <div class="p-3 rounded text-white text-start"
                                     :class="success ? 'bg-success' : 'bg-danger'">
                                    <strong>Sonuç:</strong> <span x-text="apiResult"></span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </template>

</div>

<script>
    function ztApp() {
        return {
            token: localStorage.getItem('zt_token'),
            role: localStorage.getItem('zt_role'),
            form: { username: '', password: '' },
            loading: false,
            error: '',
            apiResult: '',
            success: false,

            init() {
                if (this.token) {
                    // Sayfa yenilendiğinde token varsa Axios'a ekle
                    axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
                }
            },

            async login() {
                this.loading = true;
                this.error = '';
                try {
                    // Axios Post İsteği
                    const res = await axios.post('api.php?action=login', this.form);
                    
                    // Başarılıysa verileri kaydet
                    this.token = res.data.token;
                    this.role = res.data.role;
                    localStorage.setItem('zt_token', this.token);
                    localStorage.setItem('zt_role', this.role);
                    
                    // Axios varsayılan başlığına token ekle
                    axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
                } catch (err) {
                    this.error = err.response?.data?.message || 'Bağlantı Hatası';
                }
                this.loading = false;
            },

            logout() {
                this.token = null;
                this.role = null;
                this.form = { username: '', password: '' };
                this.apiResult = '';
                localStorage.clear();
                delete axios.defaults.headers.common['Authorization'];
            },

            async req(endpoint) {
                this.apiResult = 'İstek gönderiliyor...';
                this.success = false; // Rengi sıfırla (gri/bekleme gibi)
                
                try {
                    const res = await axios.get(`api.php?action=${endpoint}`);
                    this.apiResult = res.data.data;
                    this.success = true; // Yeşil kutu
                } catch (err) {
                    this.apiResult = err.response?.data?.message || 'Erişim Reddedildi';
                    this.success = false; // Kırmızı kutu
                }
            }
        }
    }
</script>
</body>
</html>