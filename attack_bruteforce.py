import requests
import time

# --- AYARLAR ---
TARGETS = {
    "LD (Legacy)": "http://localhost/ZTDALD/ld/api.php?action=login",
    "ZTD (Zero Trust)": "http://localhost/ZTDALD/ztd/api.php?action=login"
}

# Saldırılacak Hedef (CEO)
USERNAME = "ceo"
# Yanlış şifre listesi (Saldırı simülasyonu)
PASSWORDS = ["123456", "admin", "root", "ceo123", "qwerty", "sifre", "1111", "master", "super", "secret"]

def run_bruteforce():
    print(f"\n{'='*60}")
    print(f"🔨 KABA KUVVET (BRUTE FORCE) SALDIRI TESTİ")
    print(f"🎯 Hedef Kullanıcı: {USERNAME}")
    print(f"{'='*60}\n")

    for name, url in TARGETS.items():
        print(f"[*] Hedef: {name} saldırılıyor...")
        blocked = False
        attempts = 0

        for pwd in PASSWORDS:
            attempts += 1
            try:
                # Giriş Denemesi
                r = requests.post(url, json={"username": USERNAME, "password": pwd})
                
                # ZTD'de 429 (Too Many Requests) dönerse engellendik demektir
                if r.status_code == 429:
                    print(f"   🛑 {attempts}. Denemede ENGELLENDİ! (HTTP 429 Too Many Requests)")
                    blocked = True
                    break
                
                # LD genelde hep 200 döner ama status error olur
                resp = r.json()
                if resp.get('status') == 'error':
                    print(f"   [-] {attempts}. Deneme ({pwd}): Başarısız (İzin verildi)")
                else:
                    print(f"   [+] {attempts}. Deneme ({pwd}): ŞİFRE BULUNDU!")
                    break

            except Exception as e:
                print(f"   Hata: {e}")
        
        if not blocked:
            print(f"   ⚠️  SONUÇ: {name} saldırıyı durduramadı. Tüm şifreler denendi.\n")
        else:
            print(f"   ✅ SONUÇ: {name} saldırıyı algıladı ve IP'yi blokladı.\n")

if __name__ == "__main__":
    run_bruteforce()












































































    -;lp