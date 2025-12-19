# Zero Trust vs Legacy Database Application (ZTDALD)

## Proje Konusu
Bu proje, Zero Trust güvenlik modelini ve geleneksel (Legacy) güvenlik yaklaşımlarını karşılaştıran bir parola kasası yönetim -sistemi uygulamasıdır. Kullanıcıların parola kayıtlarını güvenli bir şekilde yönetmelerini sağlayan iki farklı sistem içerir: Güvenli Zero Trust versiyonu ve güvenlik açıkları bulunan Legacy versiyonu. Bu uygulama, modern güvenlik pratikleri ile eski yöntemler arasındaki farkları göstermek amacıyla geliştirilmiştir.

## Kurulum Kılavuzu

### Gereksinimler
- PHP 7.4 veya üzeri
- MySQL 5.7 veya üzeri
- Apache/Nginx web sunucusu
- XAMPP (geliştirme ortamı için önerilir)
- Python 3.8+ (testler için)
- Requests kütüphanesi (`pip install requests`)

### XAMPP Kurulumu
1. [XAMPP'in resmi web sitesinden](https://www.apachefriends.org/download.html) işletim sisteminize uygun versiyonu indirin.
2. İndirilen kurulum dosyasını çalıştırın ve ekrandaki talimatları izleyin.
3. Kurulum tamamlandıktan sonra XAMPP Kontrol Paneli'ni açın.
4. Apache ve MySQL servislerini "Start" butonuna tıklayarak başlatın.
5. MySQL'in çalıştığından emin olduktan sonra "Admin" butonuna tıklayarak phpMyAdmin'i açın.
6. `sql.md` dosyasındaki SQL komutlarını kullanarak `ZTALDB` veritabanını ve tablolarını oluşturun.

### Proje Kurulumu
1. Projeyi web sunucunuzun kök dizinine (`htdocs` veya `www`) kopyalayın.
2. `config.php` dosyasındaki veritabanı bağlantı ayarlarını kontrol edin ve gerekirse düzenleyin.
3. Tarayıcınızda `http://localhost/ZTDALD/L/` (Legacy) ve `http://localhost/ZTDALD/ZT/` (Zero Trust) adreslerine erişerek sistemleri test edin.

### Test Ortamı Kurulumu
1. Python 3.8+ kurulu olduğundan emin olun.
2. Gerekli kütüphaneleri yükleyin: `pip install requests`
3. XAMPP'i çalıştırın ve Apache/MySQL servislerini başlatın.
4. `comprehensive_test.py` dosyasını çalıştırarak güvenlik testlerini gerçekleştirin: `python comprehensive_test.py`

## Projenin Yapısı
```
├── config.php              # Veritabanı bağlantı ayarları
├── database.php            # Güvenli veritabanı sınıfı (Zero Trust için)
├── security_config.php     # Güvenlik yapılandırması
├── security_helper.php     # Güvenlik yardımcı fonksiyonları
├── comprehensive_test.py   # Kapsamlı güvenlik testleri
├── security_test.py        # Ek güvenlik testleri
├── sql.md                  # Veritabanı şeması
├── example.md              # Örnek dokümantasyon
├── L/                      # Legacy (Güvensiz) Sistem
│   └── index.php           # Ana uygulama dosyası
└── ZT/                     # Zero Trust (Güvenli) Sistem
    └── index.php           # Ana uygulama dosyası
```

## Teknik Detaylar

### Kullanılan Teknolojiler
- **Backend**: PHP 7.4+, PDO (Veritabanı bağlantısı için)
- **Veritabanı**: MySQL
- **Frontend**: HTML, CSS, JavaScript (minimal)
- **Test**: Python 3.8+, Requests kütüphanesi

### Güvenlik Özellikleri

#### Legacy Sistem (L/)
- Temel oturum yönetimi
- SQL injection açıkları
- CSRF koruması yok
- Güvenlik başlıkları uygulanmamış
- Zayıf parola politikası

#### Zero Trust Sistem (ZT/)
- Güçlü oturum yönetimi ve zaman aşımı
- CSRF koruması
- Güvenlik başlıkları (CSP, HSTS, vb.)
- Rol tabanlı erişim kontrolü
- Şifreleme ve güvenli veri işleme
- Düzenli oturum yenileme

### Veritabanı Yapısı
- `l_users` / `zt_users`: Kullanıcı bilgileri
- `l_vault` / `zt_vault`: Parola kayıtları
- Hassasiyet seviyeleri: LOW, MEDIUM, HIGH, CRITICAL

### Test Senaryoları
`comprehensive_test.py` dosyası aşağıdaki güvenlik testlerini gerçekleştirir:
- SQL Injection saldırıları
- CSRF saldırıları
- Oturum yönetimi testleri
- Yetkilendirme bypass testleri
- Güvenlik başlıkları kontrolü

## Kullanım

### Legacy Sistem
1. `http://localhost/ZTDALD/L/` adresine gidin
2. Test kullanıcıları ile giriş yapın (admin/1, tech/1, intern/1)
3. Parola kayıtları ekleyin, düzenleyin veya silin

### Zero Trust Sistem
1. `http://localhost/ZTDALD/ZT/` adresine gidin
2. Aynı test kullanıcıları ile giriş yapın
3. Güvenlik önlemlerinin aktif olduğunu göreceksiniz

### Test Çalıştırma
```bash
python comprehensive_test.py
```

## Eğitim Amaçlı Kullanım
Bu proje, aşağıdaki konularda eğitim amaçlı kullanılabilir:
- Web uygulama güvenliği
- Zero Trust mimarisi
- Güvenlik açıkları ve exploit'ler
- Güvenli kodlama pratikleri
- PHP güvenlik en iyi uygulamaları

## Katkıda Bulunma
Bu proje eğitim amaçlıdır. Güvenlik araştırmaları ve eğitim materyali geliştirmek için katkıda bulunabilirsiniz.

## Lisans
Bu proje açık kaynak kodludur ve eğitim amaçlı kullanım için serbest bırakılmıştır.
Yunus AKAY