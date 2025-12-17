import requests
import json
import os

# YENİ KLASÖR YOLLARI
TARGETS = {
    "LEGACY (L)":   { "url": "http://localhost/ZTDALD/L/api.php",  "method": "UNSECURE" },
    "ZERO TRUST (ZT)": { "url": "http://localhost/ZTDALD/ZT/api.php", "method": "SECURE" }
}

# Saldırgan: Stajyer (Düşük Yetkili)
ATTACKER = {"username": "stajyer", "password": "123"}

def run_test():
    print(f"\n{'='*60}")
    print(f"🔒 GÜVENLİK KARŞILAŞTIRMASI: L vs ZT")
    print(f"👤 Kullanıcı: Stajyer (Yetkisiz)")
    print(f"{'='*60}\n")

    for name, config in TARGETS.items():
        print(f"[*] Hedef: {name}...")
        try:
            # 1. GİRİŞ
            s = requests.Session()
            r = s.post(f"{config['url']}?action=login", json=ATTACKER)
            token = r.json().get('token')
            
            headers = {"Authorization": f"Bearer {token}"}
            
            # 2. VERİ ÇEKME (Banka Şifresi Görünüyor mu?)
            r_data = s.get(f"{config['url']}?action=get_vault", headers=headers)
            data = r_data.json().get('data', [])
            
            critical_leak = False
            passwords_exposed = False

            for item in data:
                # Kritik veri sızıntısı kontrolü
                if item['sensitivity'] == 'CRITICAL':
                    critical_leak = True
                
                # Şifre açık mı kontrolü (ZT'de boş gelir, L'de dolu)
                if item.get('real_password') and len(item['real_password']) > 0:
                    passwords_exposed = True

            # 3. YETKİSİZ SİLME DENEMESİ (ID: 7 -> AWS Key)
            # Rastgele bir ID silmeyi dener
            r_del = s.post(f"{config['url']}?action=delete", json={'id': 7}, headers=headers)
            deleted = (r_del.status_code == 200 and r_del.json().get('status') == 'success')

            # SONUÇ YAZDIR
            print(f"   └── Kritik Veri Göründü mü?  -> {'EVET ❌' if critical_leak else 'HAYIR ✅'}")
            print(f"   └── Şifreler Açık Metin mi?  -> {'EVET ❌' if passwords_exposed else 'HAYIR ✅'}")
            print(f"   └── Stajyer Silebildi mi?    -> {'EVET ❌' if deleted else 'HAYIR ✅ (Engellendi)'}")
            print("")

        except Exception as e:
            print(f"   └── Hata: {e}\n")

if __name__ == "__main__":
    run_test()