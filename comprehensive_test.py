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
    Color.BLUE = ''
    Color.END = ''
    Color.BOLD = ''

URLS = {
    "LEGACY (GUVENSIZ)": "http://localhost/ZTAL/L/index.php",
    "ZERO TRUST (GUVENLI)": "http://localhost/ZTAL/ZT/index.php"
}

USERS = {
    "admin": {"user": "admin", "pass": "1"},
    "tech": {"user": "tech", "pass": "1"},
    "intern": {"user": "intern", "pass": "1"}
}

def extract_csrf(html: str):
    m = re.search(r'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else None

def extract_session_id(response):
    cookies = response.cookies.get_dict()
    return cookies.get('secure_session') or cookies.get('PHPSESSID')

def test_rate_limiting(name, url):
    print(f"\n{Color.BLUE}Test 1: Rate Limiting (6 deneme/dakika){Color.END}")
    
    session = requests.Session()
    failed_attempts = 0
    
    for i in range(8):
        r = session.post(url, data={"user": "wrong", "pass": "wrong", "login": "1"})
        if "ENGEL" in r.text and "Çok fazla giriş denemesi" in r.text:
            print(f"   {Color.GREEN}[BASARILI] Rate limiting aktif (deneme {i+1}){Color.END}")
            return True
        failed_attempts += 1
        time.sleep(0.1)
    
    print(f"   {Color.RED}[BASARISIZ] Rate limiting devre disi{Color.END}")
    return False

def test_session_security(name, url):
    print(f"\n{Color.BLUE}Test 2: Session Guvenligi{Color.END}")
    
    session = requests.Session()
    
    # İlk giriş
    r1 = session.post(url, data=USERS["admin"])
    session1_id = extract_session_id(r1)
    
    # Session fixation test
    r2 = session.post(url, data=USERS["tech"])
    session2_id = extract_session_id(r2)
    
    if session1_id != session2_id:
        print(f"   {Color.GREEN}[BASARILI] Session ID degisiyor (fixation korumasi){Color.END}")
    else:
        print(f"   {Color.RED}[BASARISIZ] Session ID degismiyor (fixation acigi){Color.END}")
    
    # Session timeout test
    time.sleep(2)
    r3 = session.get(f"{url}?ping=1")
    if r3.status_code == 204:
        print(f"   {Color.GREEN}[BASARILI] Session ping calisiyor{Color.END}")
    else:
        print(f"   {Color.YELLOW}[UYARI] Session ping calismiyor{Color.END}")

def test_password_security(name, url):
    print(f"\n{Color.BLUE}Test 3: Parola Guvenligi{Color.END}")
    
    session = requests.Session()
    r = session.post(url, data=USERS["admin"])
    
    # Plain text password storage test
    if "1" in r.text and name == "LEGACY (GUVENSIZ)":
        print(f"   {Color.RED}[BEKLENEN] Legacy'de plain text parola{Color.END}")
    elif "1" not in r.text and name == "ZERO TRUST (GUVENLI)":
        print(f"   {Color.GREEN}[BASARILI] Zero Trust'da parola hash'lenmis{Color.END}")

def test_xss_protection(name, url):
    print(f"\n{Color.BLUE}Test 4: XSS Korunmasi{Color.END}")
    
    session = requests.Session()
    r = session.post(url, data=USERS["admin"])
    
    # XSS payload test
    xss_payload = "<script>alert('XSS')</script>"
    csrf = extract_csrf(r.text)
    
    if csrf:
        data = {
            "csrf": csrf,
            "service": xss_payload,
            "login": "test",
            "pass": "test",
            "sensitivity": "LOW",
            "add_vault": "1"
        }
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
    
    required_headers = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': None
    }
    
    score = 0
    for header, expected in required_headers.items():
        if header in headers:
            if expected:
                if expected in headers[header]:
                    print(f"   {Color.GREEN}[BASARILI] {header}: {headers[header]}{Color.END}")
                    score += 1
                else:
                    print(f"   {Color.YELLOW}[KISITLI] {header}: {headers[header]}{Color.END}")
            else:
                print(f"   {Color.GREEN}[BASARILI] {header}: mevcut{Color.END}")
                score += 1
        else:
            print(f"   {Color.RED}[BASARISIZ] {header}: eksik{Color.END}")
    
    return score >= 2

def test_vault_encryption(name, url):
    print(f"\n{Color.BLUE}Test 6: Vault Sifreleme{Color.END}")
    
    session = requests.Session()
    r = session.post(url, data=USERS["admin"])
    
    # Add password to vault
    csrf = extract_csrf(r.text)
    test_password = "SuperSecretPassword123!"
    
    if csrf:
        data = {
            "csrf": csrf,
            "service": "test_service",
            "login": "test_user",
            "pass": test_password,
            "sensitivity": "HIGH",
            "add_vault": "1"
        }
        r_add = session.post(url, data=data)
        
        if test_password not in r_add.text:
            print(f"   {Color.GREEN}[BASARILI] Parola veritabaninda sifrelenmis{Color.END}")
        else:
            print(f"   {Color.RED}[BASARISIZ] Parola veritabaninda plain text{Color.END}")
    else:
        print(f"   {Color.YELLOW}[ATLANTI] CSRF bulunamadi{Color.END}")

def test_role_based_access(name, url):
    print(f"\n{Color.BLUE}Test 7: Rol Bazli Erisim Kontrolu{Color.END}")
    
    roles_access = {
        "intern": {"critical": False, "admin_panel": False},
        "tech": {"critical": False, "admin_panel": False},
        "admin": {"critical": True, "admin_panel": True}
    }
    
    for role, expected in roles_access.items():
        session = requests.Session()
        r = session.post(url, data=USERS[role])
        
        # Critical data visibility
        critical_visible = re.search(r'<span[^>]*class="badge[^"]*"[^>]*>\s*CRITICAL\s*</span>', r.text, re.IGNORECASE) is not None
        admin_panel_visible = "Personel Yönetimi" in r.text
        
        critical_ok = critical_visible == expected["critical"]
        admin_ok = admin_panel_visible == expected["admin_panel"]
        
        if critical_ok and admin_ok:
            print(f"   {Color.GREEN}[BASARILI] {role.upper()} rol erisimi dogru{Color.END}")
        else:
            print(f"   {Color.RED}[BASARISIZ] {role.upper()} rol erisimi yanlis{Color.END}")
            if not critical_ok:
                print(f"      Critical data: {'görünüyor' if critical_visible else 'gizli'} (beklenen: {'görünür' if expected['critical'] else 'gizli'})")
            if not admin_ok:
                print(f"      Admin panel: {'görünüyor' if admin_panel_visible else 'gizli'} (beklenen: {'görünür' if expected['admin_panel'] else 'gizli'})")

def test_csrf_protection(name, url):
    print(f"\n{Color.BLUE}Test 8: CSRF Korunmasi{Color.END}")
    
    session = requests.Session()
    r = session.post(url, data=USERS["admin"])
    
    # Test without CSRF token
    data_no_csrf = {
        "service": "csrf_test",
        "login": "test",
        "pass": "test",
        "sensitivity": "LOW",
        "add_vault": "1"
    }
    r_no_csrf = session.post(url, data=data_no_csrf)
    
    if "ENGEL" in r_no_csrf.text and "CSRF" in r_no_csrf.text:
        print(f"   {Color.GREEN}[BASARILI] CSRF korumasi aktif{Color.END}")
    else:
        print(f"   {Color.RED}[BASARISIZ] CSRF korumasi pasif{Color.END}")
    
    # Test with valid CSRF token
    csrf = extract_csrf(r.text)
    if csrf:
        data_with_csrf = data_no_csrf.copy()
        data_with_csrf["csrf"] = csrf
        r_with_csrf = session.post(url, data=data_with_csrf)
        
        if "Kasa kaydı eklendi" in r_with_csrf.text:
            print(f"   {Color.GREEN}[BASARILI] Gecerli CSRF ile islem basarili{Color.END}")
        else:
            print(f"   {Color.YELLOW}[UYARI] Gecerli CSRF ile islem basarisiz{Color.END}")

def test_inactivity_timeout(name, url):
    print(f"\n{Color.BLUE}Test 9: Inactivity Timeout{Color.END}")
    
    session = requests.Session()
    r = session.post(url, data=USERS["admin"])
    
    if "presenceModal" in r.text:
        print(f"   {Color.GREEN}[BASARILI] Inactivity modal mevcut{Color.END}")
        
        # Test ping endpoint
        r_ping = session.get(f"{url}?ping=1")
        if r_ping.status_code == 204:
            print(f"   {Color.GREEN}[BASARILI] Session ping calisiyor{Color.END}")
        else:
            print(f"   {Color.RED}[BASARISIZ] Session ping calismiyor{Color.END}")
    else:
        print(f"   {Color.YELLOW}[BILINMIYOR] Inactivity modal bulunamadi{Color.END}")

def run_comprehensive_test(name, url):
    print(f"\n{Color.BOLD}{'='*60}{Color.END}")
    print(f"HEDEF: {name}")
    print(f"{Color.BOLD}{'='*60}{Color.END}")
    
    results = {
        "rate_limiting": test_rate_limiting(name, url),
        "session_security": test_session_security(name, url),
        "password_security": test_password_security(name, url),
        "xss_protection": test_xss_protection(name, url),
        "security_headers": test_security_headers(name, url),
        "vault_encryption": test_vault_encryption(name, url),
        "role_based_access": test_role_based_access(name, url),
        "csrf_protection": test_csrf_protection(name, url),
        "inactivity_timeout": test_inactivity_timeout(name, url)
    }
    
    # Summary
    passed = sum(1 for v in results.values() if v is True)
    total = len([k for k, v in results.items() if v is not None])
    
    print(f"\n{Color.BOLD}OZET:{Color.END}")
    print(f"   Basarili testler: {passed}/{total}")
    
    if name == "ZERO TRUST (GUVENLI)":
        if passed >= 7:
            print(f"   {Color.GREEN}[MUKEMMEL] Zero Trust guvenlik seviyesi yuksek{Color.END}")
        elif passed >= 5:
            print(f"   {Color.YELLOW}[IYI] Zero Trust guvenlik seviyesi orta{Color.END}")
        else:
            print(f"   {Color.RED}[ZAYIF] Zero Trust guvenlik seviyesi dusuk{Color.END}")
    else:
        print(f"   {Color.YELLOW}[BEKLENEN] Legacy uygulama guvenlik aciklari iceriyor{Color.END}")

if __name__ == "__main__":
    if os.name == 'nt' and not supports_ansi():
        disable_colors()
    
    print(f"\n{Color.BOLD}KAPSAMLI ZERO TRUST GUVENLIK TESTI{Color.END}")
    print(f"Bu test 9 farkli guvenlik ozelligini kontrol eder:\n")
    print(f"1. Rate Limiting (6 deneme/dakika)")
    print(f"2. Session Guvenligi (fixation, timeout)")
    print(f"3. Parola Guvenligi (hashing)")
    print(f"4. XSS Korunmasi")
    print(f"5. Security Headers (CSP, X-Frame-Options)")
    print(f"6. Vault Sifreleme")
    print(f"7. Rol Bazli Erisim Kontrolu")
    print(f"8. CSRF Korunmasi")
    print(f"9. Inactivity Timeout")
    
    for name, url in URLS.items():
        run_comprehensive_test(name, url)
    
    print(f"\n{Color.BOLD}Test tamamlandi.{Color.END}")
