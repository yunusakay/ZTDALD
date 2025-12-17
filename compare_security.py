import requests
import json
from datetime import datetime

# --- AYARLAR ---
TARGETS = {
    "LD (Legacy Sistem)": {
        "url": "http://localhost/ZTDALD/ld/api.php",
        "method": "SESSION" # Çerez tabanlı
    },
    "ZTD (Zero Trust)": {
        "url": "http://localhost/ZTDALD/ztd/api.php",
        "method": "TOKEN"   # Token tabanlı
    }
}

# SALDIRGAN KİMLİĞİ (İkisinde de aynı kullanıcı)
ATTACKER = {"username": "analyst", "password": "pass123"}

def run_attack():
    print(f"\n{'='*60}")
    print(f"⚔️  GÜVENLİK KARŞILAŞTIRMA TESTİ BAŞLATILIYOR ⚔️")
    print(f"⏰ Zaman: {datetime.now().strftime('%H:%M:%S')}")
    print(f"👤 Saldırgan: {ATTACKER['username']} (Düşük Yetkili)")
    print(f"{'='*60}\n")

    results = {}

    for name, config in TARGETS.items():
        print(f"[*] Hedef: {name} taranıyor...")
        base_url = config['url']
        
        # 1. ADIM: GİRİŞ YAP (AUTHENTICATION)
        session = requests.Session()
        token = None
        
        try:
            # Login isteği at (Her ikisi için aynı endpoint)
            r_login = session.post(f"{base_url}?action=login", json=ATTACKER)
            resp_json = r_login.json()

            if resp_json.get('status') != 'success':
                print(f"   [-] {name}: Giriş Başarısız! Test iptal.")
                continue

            # Token varsa al (ZTD için), yoksa Session (LD için) devam eder
            if config['method'] == 'TOKEN':
                token = resp_json.get('token')
                headers = {"Authorization": f"Bearer {token}"}
            else:
                headers = {} # LD cookie kullanır, headers boş kalabilir

        except Exception as e:
            print(f"   [-] Bağlantı Hatası: {e}")
            continue

        # 2. ADIM: VERİ ÇALMA (EXFILTRATION)
        # Aynı veriyi istiyoruz: "get_stats"
        try:
            if config['method'] == 'TOKEN':
                r_data = requests.get(f"{base_url}?action=get_stats", headers=headers)
            else:
                r_data = session.get(f"{base_url}?action=get_stats")
            
            data = r_data.json().get('data', [])
        except:
            data = []

        # 3. ADIM: ANALİZ (CEO VERİSİ VAR MI?)
        leaked_count = len(data)
        ceo_exposed = False
        
        for user in data:
            if user['username'] == 'ceo':
                ceo_exposed = True
                break
        
        results[name] = {
            "total_records": leaked_count,
            "ceo_leaked": ceo_exposed,
            "data_sample": [u['username'] for u in data]
        }
        print(f"   [+] {name} taraması tamamlandı.\n")

    # --- RAPORLAMA ---
    print(f"{'='*60}")
    print(f"📊 SONUÇ TABLOSU")
    print(f"{'='*60}")
    print(f"{'SİSTEM':<20} | {'GÖRÜNEN KAYIT':<15} | {'CEO SIZINTISI?':<15} | {'DURUM':<10}")
    print("-" * 70)

    for name, res in results.items():
        if res['ceo_leaked']:
            status = "❌ GÜVENSİZ"
            leak_text = "EVET (Kritik)"
        else:
            status = "✅ GÜVENLİ"
            leak_text = "HAYIR"
            
        print(f"{name:<20} | {res['total_records']:<15} | {leak_text:<15} | {status:<10}")
    
    print("-" * 70)
    print("\n📝 YORUM:")
    print("LD (Legacy), yetki kontrolü yapmadığı için Analyst'e herkesi gösterdi.")
    print("ZTD (Zero Trust), 'Data Scoping' yaparak Analyst'e sadece kendini gösterdi.")

if __name__ == "__main__":
    run_attack()