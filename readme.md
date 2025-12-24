# Zero Trust vs Legacy Database Application (ZTDALD)

## Proje Konusu
Bu proje, Zero Trust güvenlik modelini ve geleneksel (Legacy) güvenlik yaklaşımlarını karşılaştıran bir parola kasası yönetim sistemidir. Kullanıcıların parola kayıtlarını güvenli bir şekilde yönetmelerini sağlayan iki farklı sistem içerir: Güvenli Zero Trust versiyonu ve güvenlik açıkları bulunan Legacy versiyonu. Bu uygulama, modern güvenlik pratikleri ile eski yöntemler arasındaki farkları göstermek amacıyla geliştirilmiştir.

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