import requests
import sys
import re
import os
import time
import hashlib
from urllib.parse import urlparse, parse_qs

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def supports_ansi() -> bool:
    if not sys.stdout.isatty(): return False
    term = (os.environ.get('TERM') or '').lower()
    if term in ('', 'dumb'): return False
    return True

def disable_colors():
    Color.RED = ''; Color.GREEN = ''; Color.YELLOW = ''; Color.BLUE = ''; Color.END = ''; Color.BOLD = ''

URLS = {
    "LEGACY (GUVENSIZ)": "http://localhost/ZTAL/L/index.php",
    "ZERO TRUST (GUVENLI)": "http://localhost/ZTAL/ZT/index.php"
}

USERS = {
    "admin": {"user": "admin", "pass": "1234"},
    "tech": {"user": "tech", "pass": "1234"},
    "intern": {"user": "intern", "pass": "1234"}
}

def extract_csrf(html: str):
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None

def extract_session_id(session):
    cookies = session.cookies.get_dict()
    return cookies.get('secure_session') or cookies.get('PHPSESSID')

def test_rate_limiting(name, url):
    print(f"\n{Color.BLUE}Test 1: Rate Limiting (6 deneme/dakika){Color.END}")
    session = requests.Session()
    for i in range(8):
        r = session.post(url, data={"user": "wrong", "pass": "wrong", "login": "1"})
        if "ENGEL" in r.text:
            print(f"   {Color.GREEN}[BASARILI] Rate limiting aktif (deneme {i+1}){Color.END}")
            return True
        time.sleep(0.1)
    print(f"   {Color.RED}[BASARISIZ] Rate limiting devre disi{Color.END}")
    return False

def test_session_security(name, url):
    print(f"\n{Color.BLUE}Test 2: Session Guvenligi{Color.END}")
    session = requests.Session()
    
    # İlk giriş
    session.post(url, data={"user": "admin", "pass": "1234", "login": "1"})
    session1_id = extract_session_id(session)
    
    if not session1_id:
        print(f"   {Color.YELLOW}[HATA] Giris yapilamadi (Session ID yok).{Color.END}")
    else:
        # Session fixation test
        session.post(url, data={"user": "tech", "pass": "1234", "login": "1"})
        session2_id = extract_session_id(session)
        
        if session1_id != session2_id:
            print(f"   {Color.GREEN}[BASARILI] Session ID degisiyor (fixation korumasi){Color.END}")
        else:
            print(f"   {Color.RED}[BASARISIZ] Session ID degismiyor (fixation acigi){Color.END}")
    
    # Ping test
    time.sleep(1)
    r3 = session.get(f"{url}?ping=1")
    if r3.status_code == 204:
        print(f"   {Color.GREEN}[BASARILI] Session ping calisiyor{Color.END}")
    else:
        print(f"   {Color.YELLOW}[UYARI] Session ping calismiyor{Color.END}")

def test_password_security(name, url):
    print(f"\n{Color.BLUE}Test 3: Parola Guvenligi{Color.END}")
    session = requests.Session()
    r = session.post(url, data={"user": "admin", "pass": "1234", "login": "1"})
    if "1234" in r.text and name == "LEGACY (GUVENSIZ)":
        print(f"   {Color.RED}[BEKLENEN] Legacy'de plain text parola{Color.END}")
    elif "1234" not in r.text and name == "ZERO TRUST (GUVENLI)":
        print(f"   {Color.GREEN}[BASARILI] Zero Trust'da parola hash'lenmis/gizlenmis{Color.END}")

def test_xss_protection(name, url):
    print(f"\n{Color.BLUE}Test 4: XSS Korunmasi{Color.END}")
    session = requests.Session()
    r = session.post(url, data={"user": "admin", "pass": "1234", "login": "1"})
    xss_payload = "<script>alert('XSS')</script>"
    csrf = extract_csrf(r.text)
    data = {"service": xss_payload, "login": "test", "pass": "test", "sensitivity": "LOW", "add_vault": "1"}
    if csrf: data["csrf"] = csrf
    
    if csrf or name == "LEGACY (GUVENSIZ)":
        r_add = session.post(url, data=data)
        if xss_payload not in r_add.text and "&lt;script&gt;" in r_add.text:
            print(f"   {Color.GREEN}[BASARILI] XSS filtreleme aktif{Color.END}")
        elif xss_payload in r_add.text:
            print(f"   {Color.RED}[BASARISIZ] XSS acigi var{Color.END}")
        else:
            print(f"   {Color.YELLOW}[BILINMIYOR] XSS testi neticesiz{Color.END}")
    else:
        print(f"   {Color.YELLOW}[ATLANTI] CSRF bulunamadi, XSS testi atlandi{Color.END}")

def test_security_headers(name, url):
    print(f"\n{Color.BLUE}Test 5: Security Headers{Color.END}")
    r = requests.get(url)
    headers = r.headers
    required = ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
    missing = [h for h in required if h not in headers]
    
    if not missing:
        print(f"   {Color.GREEN}[BASARILI] Tum guvenlik basliklari mevcut{Color.END}")
    else:
        for h in missing: print(f"   {Color.RED}[BASARISIZ] {h}: eksik{Color.END}")

def test_vault_encryption(name, url):
    print(f"\n{Color.BLUE}Test 6: Vault Sifreleme{Color.END}")
    session = requests.Session()
    r = session.post(url, data={"user": "admin", "pass": "1234", "login": "1"})
    csrf = extract_csrf(r.text)
    test_pass = "SuperSecret!"
    data = {"service": "enc_test", "login": "test", "pass": test_pass, "sensitivity": "HIGH", "add_vault": "1"}
    if csrf: data["csrf"] = csrf
    r_add = session.post(url, data=data)
    if test_pass not in r_add.text:
        print(f"   {Color.GREEN}[BASARILI] Parola veritabaninda sifrelenmis{Color.END}")
    else:
        print(f"   {Color.RED}[BASARISIZ] Parola veritabaninda plain text{Color.END}")

def test_role_based_access(name, url):
    print(f"\n{Color.BLUE}Test 7: Rol Bazli Erisim Kontrolu{Color.END}")
    roles = {
        "intern": {"crit": False, "admin": False},
        "tech": {"crit": False, "admin": False},
        "admin": {"crit": True, "admin": True}
    }
    for role, exp in roles.items():
        session = requests.Session()
        r = session.post(url, data={"user": role, "pass": "1234", "login": "1"})
        if "Giriş" in r.text or "Hatalı" in r.text:
            print(f"   {Color.RED}[HATA] {role.upper()} giris yapamadi.{Color.END}")
            continue
        
        crit = "CRITICAL" in r.text
        adm = "Personel Yönetimi" in r.text
        
        if crit == exp["crit"] and adm == exp["admin"]:
            print(f"   {Color.GREEN}[BASARILI] {role.upper()} rol erisimi dogru{Color.END}")
        else:
            print(f"   {Color.RED}[BASARISIZ] {role.upper()} rol erisimi yanlis{Color.END}")

def test_csrf_protection(name, url):
    print(f"\n{Color.BLUE}Test 8: CSRF Korunmasi{Color.END}")
    session = requests.Session()
    r = session.post(url, data={"user": "intern", "pass": "1234", "login": "1"})
    
    # 3. Test: Admin/User Silme Saldırısı (BURADA DEĞİŞİKLİK YAPILDI: ID 2 - Tech Siliniyor)
    print(f"   {Color.BLUE}Test 3 (Alt): Kullanici Silme Saldirisi (?del_user=2){Color.END}")
    
    csrf = extract_csrf(r.text)
    attack_url = f"{url}?del_user=2" # Tech kullanıcısını silmeyi dene
    if csrf: attack_url += f"&csrf={csrf}"
    
    r_attack = session.get(attack_url)
    
    if "Personel silindi" in r_attack.text:
        print(f"      {Color.RED}[KRITIK ACIK] Intern, bir kullaniciyi (ID:2) sildi!{Color.END}")
    elif "Yetkisiz" in r_attack.text or "ENGEL" in r_attack.text:
        print(f"      {Color.GREEN}[BASARILI] Silme islemi engellendi.{Color.END}")
    else:
        print(f"      {Color.YELLOW}[SONUC] Islem sonucu belirsiz.{Color.END}")

    # Normal CSRF Testi
    data_no_csrf = {"service": "csrf", "login": "test", "pass": "1", "sensitivity": "LOW", "add_vault": "1"}
    r_fail = session.post(url, data=data_no_csrf)
    if "ENGEL" in r_fail.text:
        print(f"   {Color.GREEN}[BASARILI] CSRF korumasi aktif (Token yok){Color.END}")
    else:
        print(f"   {Color.RED}[BASARISIZ] CSRF korumasi pasif (Token yok){Color.END}")
    
    if csrf:
        data_ok = data_no_csrf.copy()
        data_ok["csrf"] = csrf
        r_ok = session.post(url, data=data_ok)
        if "Kasa kaydı eklendi" in r_ok.text:
            print(f"   {Color.GREEN}[BASARILI] Gecerli CSRF ile islem basarili{Color.END}")

def test_inactivity(name, url):
    print(f"\n{Color.BLUE}Test 9: Inactivity Timeout{Color.END}")
    session = requests.Session()
    r = session.post(url, data={"user": "admin", "pass": "1234", "login": "1"})
    if "presenceModal" in r.text:
        print(f"   {Color.GREEN}[BASARILI] Inactivity modal mevcut{Color.END}")
    else:
        print(f"   {Color.YELLOW}[BILINMIYOR] Inactivity modal bulunamadi{Color.END}")

def run_test(name, url):
    print(f"\n{Color.BOLD}{'='*60}\nHEDEF: {name}\n{'='*60}{Color.END}")
    test_rate_limiting(name, url)
    test_session_security(name, url)
    test_password_security(name, url)
    test_xss_protection(name, url)
    test_security_headers(name, url)
    test_vault_encryption(name, url)
    test_role_based_access(name, url)
    test_csrf_protection(name, url)
    test_inactivity(name, url)

if __name__ == "__main__":
    if os.name == 'nt' and not supports_ansi(): disable_colors()
    print(f"\n{Color.BOLD}KAPSAMLI ZERO TRUST GUVENLIK TESTI{Color.END}")
    for n, u in URLS.items(): run_test(n, u)
    print("\nTest tamamlandi.")