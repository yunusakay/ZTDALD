<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Legacy Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>body{background:#fff0f0;}</style>
</head>
<body>

<div x-data="app()" class="container mt-5">

    <template x-if="!auth">
        <div class="card mx-auto" style="max-width:400px">
            <div class="card-header bg-danger text-white">Legacy Login</div>
            <div class="card-body">
                <input x-model="user" type="text" class="form-control mb-2" placeholder="Username">
                <input x-model="pass" type="password" class="form-control mb-2" placeholder="Password">
                <button @click="login" class="btn btn-danger w-100">Login</button>
            </div>
        </div>
    </template>

    <template x-if="auth">
        <div>
            <nav class="navbar bg-white shadow p-3 mb-4 d-flex justify-content-between">
                <span class="text-danger fw-bold">LD System</span>
                <button @click="logout" class="btn btn-sm btn-outline-danger">Exit</button>
            </nav>

            <div class="card text-center">
                <div class="card-header bg-danger text-white">Actions</div>
                <div class="card-body">
                    <button @click="getData('view')" class="btn btn-secondary">View Data</button>
                    <button @click="getData('admin_data')" class="btn btn-danger">Admin Data (Attack)</button>
                    
                    <div class="mt-3" x-show="res">
                        <pre x-text="JSON.stringify(res, null, 2)" class="bg-dark text-white p-3 text-start"></pre>
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
            user: '', pass: '',
            res: null,

            async login() {
                const r = await axios.post('api.php?action=login', {username:this.user, password:this.pass});
                if(r.data.status === 'success') this.auth = true;
                else alert('Error');
            },
            async logout() {
                await axios.get('api.php?action=logout');
                this.auth = false; this.res = null; this.user=''; this.pass='';
            },
            async getData(act) {
                try {
                    const r = await axios.get(`api.php?action=${act}`);
                    this.res = r.data;
                } catch(e) { this.res = 'Error'; }
            }
        }
    }
</script>
</body>
</html>