import requests
import sys
import re
import os

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    END = '\033[0m'
    BOLD = '\033[1m'

def supports_ansi() -> bool:
    if not sys.stdout.isatty(): return False
    term = (os.environ.get('TERM') or '').lower()
    if term in ('', 'dumb'): return False
    return True

def disable_colors():
    Color.RED = ''; Color.GREEN = ''; Color.YELLOW = ''; Color.END = ''; Color.BOLD = ''

URLS = {
    "LEGACY (GUVENSIZ)": "http://localhost/ZTAL/L/index.php",
    "ZERO TRUST (GUVENLI)": "http://localhost/ZTAL/ZT/index.php"
}

# ŞİFRELER GÜNCELLENDİ: 1234
ATTACKER = {
    "user": "intern",
    "pass": "1234",
    "login": "1"
}

def extract_csrf(html: str):
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None

def check_security(name, url):
    print(f"\n{Color.BOLD}{'-'*60}{Color.END}")
    print(f"HEDEF: {name}")
    print(f"{Color.BOLD}{'-'*60}{Color.END}")

    session = requests.Session()

    print(f"[*] Intern olarak giriş yapılıyor...")
    try:
        r = session.post(url, data=ATTACKER)
        if "Çıkış" not in r.text and "ZT Vault" not in r.text and "Legacy Vault" not in r.text:
            print(f"{Color.RED}[!] Giris basarisiz. HTTP: {r.status_code}{Color.END}")
            return
    except Exception as e:
        print(f"{Color.RED}[!] Hata: {e}{Color.END}")
        return

    # Test 1: CRITICAL Data Leak
    critical_leaked = "CRITICAL" in r.text
    print(f"   └── Test 1: Kritik Veri Sızıntısı (CRITICAL)")
    if critical_leaked:
        print(f"       {Color.RED}[BASARISIZ] Intern kritik verileri goruyor!{Color.END}")
    else:
        print(f"       {Color.GREEN}[BASARILI] Kritik veriler gizlendi.{Color.END}")

    # Test 2: Admin Panel Visibility
    user_management_visible = "Personel Yönetimi" in r.text
    print(f"   └── Test 2: Admin Paneli Görünürlüğü")
    if user_management_visible:
        print(f"       {Color.RED}[BASARISIZ] Intern personel yonetimini goruyor!{Color.END}")
    else:
        print(f"       {Color.GREEN}[BASARILI] Panel gizli.{Color.END}")

    # Test 3: Admin Deletion Attack
    print(f"   └── Test 3: Admin Silme Saldırısı (?del_user=1)")
    
    csrf = extract_csrf(r.text)
    # Admin ID genellikle 1'dir.
    attack_url = f"{url}?del_user=1" 
    if csrf:
        attack_url = f"{attack_url}&csrf={csrf}"
    
    r_attack = session.get(attack_url)
    
    if "Personel silindi" in r_attack.text:
        print(f"       {Color.RED}[KRITIK ACIK] Intern, admin hesabini sildi!{Color.END}")
    elif "Yetkisiz" in r_attack.text or "ENGEL" in r_attack.text:
        print(f"       {Color.GREEN}[BLOKLANDI] Sistem saldiriyi engelledi.{Color.END}")
    else:
        # Check if admin is still there by logging in as admin (requires new session)
        print(f"       {Color.YELLOW}[SONUC] Islem engellendi veya yetki yetmedi.{Color.END}")

if __name__ == "__main__":
    if os.name == 'nt' and not supports_ansi():
        disable_colors()
    print(f"\n{Color.BOLD}SIBER GUVENLIK TESTI BASLATILIYOR{Color.END}")
    for name, url in URLS.items():
        check_security(name, url)
    print("\nTest tamamlandi.")