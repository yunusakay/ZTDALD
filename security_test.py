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
    if not sys.stdout.isatty():
        return False
    term = (os.environ.get('TERM') or '').lower()
    if term in ('', 'dumb'):
        return False
    return True

def disable_colors():
    Color.RED = ''
    Color.GREEN = ''
    Color.YELLOW = ''
    Color.END = ''
    Color.BOLD = ''

URLS = {
    "LEGACY (GUVENSIZ)": "http://localhost/ZTAL/L/index.php",
    "ZERO TRUST (GUVENLI)": "http://localhost/ZTAL/ZT/index.php"
}

ATTACKER = {
    "user": "intern",
    "pass": "1",
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
        if "Çıkış" not in r.text:
            preview = re.sub(r"\s+", " ", r.text)[:200]
            print(f"{Color.RED}[!] Giris basarisiz. HTTP: {r.status_code}{Color.END}")
            print(f"{Color.YELLOW}    Cevap onizleme: {preview}{Color.END}")
            return
    except Exception as e:
        print(f"{Color.RED}[!] Hata: {e}{Color.END}")
        return

    critical_leaked = re.search(r'<span[^>]*class="badge[^\"]*"[^>]*>\s*CRITICAL\s*</span>', r.text, re.IGNORECASE) is not None
    
    print(f"   └── Test 1: Kritik Veri Sızıntısı (CRITICAL)")
    if critical_leaked:
        print(f"       {Color.RED}[BASARISIZ] Intern kritik verileri goruyor!{Color.END}")
    else:
        print(f"       {Color.GREEN}[BASARILI] Kritik veriler gizlendi.{Color.END}")

    user_management_visible = "Personel Yönetimi" in r.text
    
    print(f"   └── Test 2: Admin Paneli Görünürlüğü")
    if user_management_visible:
        print(f"       {Color.RED}[BASARISIZ] Intern personel yonetimini goruyor!{Color.END}")
    else:
        print(f"       {Color.GREEN}[BASARILI] Panel gizli.{Color.END}")

    print(f"   └── Test 3: Admin Silme Saldırısı (?del_user=3)")

    csrf = extract_csrf(r.text)
    attack_url = f"{url}?del_user=3"
    if csrf:
        attack_url = f"{attack_url}&csrf={csrf}"
    r_attack = session.get(attack_url)
    
    if "Personel Silindi" in r_attack.text or "Kullanıcı Silindi" in r_attack.text:
        print(f"       {Color.RED}[KRITIK ACIK] Intern, admin hesabini sildi!{Color.END}")
    elif "Yetkisiz" in r_attack.text or "ENGEL" in r_attack.text:
        print(f"       {Color.GREEN}[BLOKLANDI] Sistem saldiriyi engelledi.{Color.END}")
    else:
        if "admin" not in r_attack.text:
             print(f"       {Color.RED}[KRITIK ACIK] Admin listeden kayboldu!{Color.END}")
        else:
             print(f"       {Color.GREEN}[KORUNDU] Admin hala duruyor.{Color.END}")

if __name__ == "__main__":
    if os.name == 'nt' and not supports_ansi():
        disable_colors()
    print(f"\n{Color.BOLD}SIBER GUVENLIK TESTI BASLATILIYOR (HTML/Session Modu){Color.END}")
    for name, url in URLS.items():
        check_security(name, url)
    print("\nTest tamamlandi.")