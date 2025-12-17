<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Kurumsal Performans Paneli</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>body { background-color: #f4f6f9; }</style>
</head>
<body>

<div x-data="app()" class="container mt-5">

    <template x-if="!auth">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card shadow border-0">
                    <div class="card-body p-4 text-center">
                        <div class="mb-4">
                            <h4 class="text-secondary fw-bold">Personel Girişi</h4>
                            <small class="text-muted">Kurumsal Yönetim Sistemi</small>
                        </div>
                        <input x-model="user" class="form-control mb-3" placeholder="Kullanıcı Adı">
                        <input x-model="pass" type="password" class="form-control mb-3" placeholder="Şifre">
                        <button @click="login" class="btn btn-secondary w-100">Giriş Yap</button>
                    </div>
                </div>
            </div>
        </div>
    </template>

    <template x-if="auth">
        <div>
            <nav class="navbar bg-white shadow-sm p-3 mb-4 rounded d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <span class="fs-5 fw-bold text-secondary me-2">📊</span>
                    <span class="fw-bold text-dark">Şirket Performans Paneli</span>
                </div>
                <button @click="logout" class="btn btn-sm btn-outline-secondary">Çıkış</button>
            </nav>

            <div class="row">
                <div class="col-md-4">
                    <div class="card shadow-sm border-0 mb-3">
                        <div class="card-body text-center p-4">
                            <div class="mb-3">
                                <span class="display-6">👤</span>
                            </div>
                            <h5 class="card-title">Hoşgeldiniz</h5>
                            <h3 class="fw-light text-primary my-3" x-text="user"></h3>
                            <span class="badge bg-secondary px-3 py-2 rounded-pill">Personel</span>
                        </div>
                    </div>
                </div>

                <div class="col-md-8">
                    <div class="card shadow-sm border-0">
                        <div class="card-header bg-white py-3">
                            <h6 class="mb-0 fw-bold text-secondary">Maaş / Performans Dağılımı</h6>
                        </div>
                        <div class="card-body">
                            <canvas id="myChart" style="max-height: 300px;"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </template>

</div>

<script>
    function app() {
        return {
            auth: false,
            user: '', 
            pass: '', 
            chart: null,

            async login() {
                try {
                    const r = await axios.post('api.php?action=login', {username:this.user, password:this.pass});
                    if(r.data.status === 'success') {
                        this.auth = true;
                        setTimeout(() => this.loadChart(), 100);
                    } else {
                        alert('Hatalı giriş!');
                    }
                } catch (e) {
                    alert('Bağlantı hatası!');
                }
            },

            async logout() {
                await axios.get('api.php?action=logout');
                this.auth = false;
                this.user = '';
                this.pass = '';
                location.reload();
            },

            async loadChart() {
                const r = await axios.get('api.php?action=get_stats');
                const data = r.data.data;

                const ctx = document.getElementById('myChart');
                if(this.chart) this.chart.destroy();

                this.chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.map(d => d.username),
                        datasets: [{
                            label: 'Aylık Değer (TL)',
                            data: data.map(d => d.score),
                            backgroundColor: '#6c757d', // Kurumsal Gri
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: { y: { beginAtZero: true } },
                        plugins: { legend: { display: false } }
                    }
                });
            }
        }
    }
</script>
</body>
</html>