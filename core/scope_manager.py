"""
core/scope_manager.py

===================================================================
BYTEWALL - SCOPE MANAGER
===================================================================
Bu dosya, ByteWall projesinin EN KRİTİK güvenlik bileşenidir.
Görevi tek cümleyle: "Hangi hedeflere dokunmamıza izin var, hangilerine yok?"

----------------------------------------------------------------
NEDEN BU DOSYA BU KADAR ÖNEMLİ?
----------------------------------------------------------------
Bug bounty programlarının hepsinin bir "scope" (kapsam) tanımı vardır:
  - "Bu domainleri tarayabilirsin"        -> in_scope
  - "Bu domainlere KESİNLİKLE DOKUNMA"    -> out_of_scope

Eğer sistem yanlışlıkla scope dışı bir siteyi tararsa:
  - Bug bounty programından yasaklanabilirsin
  - Yasal sorumluluk doğabilir (izinsiz sisteme saldırı sayılır)
  - Üçüncü taraf bir şirketin sistemine zarar verebilirsin

Bu yüzden bu dosyanın mantığı "temkinli" tasarlanmıştır:
ŞÜPHE DURUMUNDA HER ZAMAN REDDET.

----------------------------------------------------------------
TEMEL FELSEFE: WHITELIST (İZİN VERİLENLER LİSTESİ)
----------------------------------------------------------------
İki farklı güvenlik felsefesi vardır:

  BLACKLIST (kara liste) mantığı:
    "Yasaklı listede olmayan HER ŞEYE izin ver"
    -> Tehlikeli çünkü bir şeyi yasaklı listeye eklemeyi UNUTURSAN
       otomatik olarak izin verilmiş olur.

  WHITELIST (beyaz liste) mantığı -- BİZİM KULLANDIĞIMIZ:
    "İzin verilenler listesinde olmayan HER ŞEYİ reddet"
    -> Güvenli çünkü bir şeyi izin listesine eklemeyi unutursan
       otomatik olarak REDDEDİLİR. Hata payı güvenli tarafta kalır.

Bu dosyadaki HER karar bu felsefeye göre şekillenmiştir.

----------------------------------------------------------------
KARAR ÖNCELİK SIRASI (bir hedef değerlendirilirken)
----------------------------------------------------------------
Bir hedef geldiğinde şu sırayla kontrol edilir:

  ADIM 1: out_of_scope listesine uyuyor mu?
          -> UYUYORSA HEMEN REDDET. (in_scope'ta bile olsa fark etmez!)
             Örnek: "*.example.com" in_scope'ta olsa bile,
             "internal.example.com" ayrıca out_of_scope'ta yazıyorsa
             REDDEDİLİR. Çünkü out_of_scope her zaman kazanır.

  ADIM 2: in_scope listesine uyuyor mu?
          -> UYUYORSA KABUL ET.

  ADIM 3: Hiçbirine uymuyorsa?
          -> REDDET. (varsayılan davranış budur, whitelist mantığı gereği)

----------------------------------------------------------------
DESTEKLENEN HEDEF FORMATLARI
----------------------------------------------------------------
  - Tam domain isimleri:     "api.example.com"
  - Wildcard (joker) domain: "*.example.com"  (tüm alt domainleri kapsar)
  - Tekil IP adresi:         "203.0.113.10"
  - IP aralığı (CIDR):       "203.0.113.0/24"
  - Tam URL (otomatik ayrıştırılır, sadece hostname kısmı kullanılır):
        "https://api.example.com:8443/path?x=1" -> "api.example.com"
"""

from __future__ import annotations

# --- Standart kütüphaneler ---
import fnmatch      # Wildcard (joker karakter) eşleştirme için: "*.example.com" gibi
import ipaddress    # IP adresi ve CIDR aralığı (203.0.113.0/24) doğrulama/eşleştirme için
import logging      # Her kararın (kabul/red) kayıt altına alınması için — denetlenebilirlik şart
from dataclasses import dataclass, field   # Basit, tip-güvenli veri taşıyıcı sınıflar için
from pathlib import Path                   # Dosya yollarını işletim sisteminden bağımsız yönetmek için
from urllib.parse import urlparse          # "https://x.com/path" gibi URL'lerden hostname çıkarmak için

# --- Dış kütüphaneler ---
import yaml          # program.yaml dosyasını okumak için (PyYAML)
from pydantic import BaseModel, ValidationError, field_validator
# Pydantic: program.yaml'dan okuduğumuz veriyi otomatik doğrular.
# Örneğin "program_name" eksikse, ya da "in_scope" bir liste değilse,
# kod ÇALIŞMAYA BAŞLAMADAN hata fırlatır. Bu, "sessizce yanlış davranma"
# riskini en baştan keser.

# Bu modül için özel bir logger oluşturuyoruz.
# Neden print() değil de logging? Çünkü logging seviyelere ayrılabilir
# (INFO, WARNING, ERROR), dosyaya yazılabilir, zaman damgası otomatik eklenir.
logger = logging.getLogger("bytewall.scope_manager")


# ===================================================================
# ÖZEL HATA SINIFLARI
# ===================================================================
# Python'da genel "Exception" fırlatmak yerine kendi özel hata
# sınıflarımızı tanımlıyoruz. Bunun faydası: kodu kullanan kişi
# (orchestrator.py) hangi TÜR hatanın oluştuğunu ayırt edebilir.
# Örneğin "dosya bulunamadı" ile "dosya bozuk" farklı şeylerdir,
# farklı şekilde ele alınmak isteyebilir.

class ScopeFileError(Exception):
    """
    program.yaml dosyasıyla ilgili DOSYA SEVİYESİNDE bir sorun var:
    - Dosya hiç yok
    - Dosya okunamıyor (izin sorunu vs.)
    - Dosyanın içeriği geçerli YAML formatında değil (syntax hatası)
    """


class ScopeValidationError(Exception):
    """
    Dosya okunabildi ve geçerli YAML ama İÇERİĞİ beklediğimiz
    şemaya uymuyor. Örnek: "program_name" alanı eksik,
    ya da "in_scope" boş bir liste (bu da tehlikelidir çünkü
    boş liste = her şeyi reddet demek, ama bunu KASITLI mı yaptın
    yoksa YANLIŞLIKLA mı boş bıraktın belli değil, o yüzden hata veriyoruz).
    """


# ===================================================================
# PROGRAM.YAML ŞEMASI (Pydantic modeli)
# ===================================================================
# Bu sınıf, program.yaml dosyasının "şeklini" tanımlar.
# Pydantic, YAML'dan gelen ham veriyi bu şekle uydurmaya çalışır.
# Uymazsa (tip yanlışsa, alan eksikse) otomatik olarak hata fırlatır.
# Bu sayede "scope_manager.py"nin geri kalanında, elimizdeki verinin
# DOĞRU FORMATTA olduğundan her zaman eminiz — sürekli "acaba bu alan
# var mı, tipi doğru mu" diye kontrol etmemize gerek kalmıyor.

class ProgramSchema(BaseModel):
    program_name: str          # Programın adı (sadece bilgi/log amaçlı)
    in_scope: list[str]        # İzin verilen hedef pattern'lerinin listesi (ZORUNLU)
    out_of_scope: list[str] = []   # Yasaklı pattern'ler (opsiyonel, varsayılan: boş liste)
    notes: str = ""             # Serbest metin notlar (opsiyonel)

    # Pydantic'e özel bir "validator" (doğrulayıcı) fonksiyon ekliyoruz.
    # Bu fonksiyon, "in_scope" alanı okunduktan HEMEN SONRA otomatik çalışır.
    @field_validator("in_scope")
    @classmethod
    def in_scope_not_empty(cls, v: list[str]) -> list[str]:
        # Neden boş in_scope'u özellikle yasaklıyoruz?
        # Çünkü boş liste teknik olarak "hiçbir şey kabul edilmez" anlamına
        # gelir (whitelist mantığı gereği). Bu MANTIKEN doğru bir davranış
        # olsa da, kullanıcı muhtemelen yanlışlıkla dosyayı boş bırakmıştır.
        # Bu yüzden sessizce "her şeyi reddet" yerine, AÇIKÇA hata veririz
        # ki kullanıcı hatasını fark etsin.
        if not v:
            raise ValueError(
                "in_scope boş olamaz — boş liste her şeyi otomatik reddeder "
                "(bu istenen davranış olabilir ama açıkça kontrol et)."
            )
        return v  # Doğrulama geçtiyse, değeri olduğu gibi geri döndür


# ===================================================================
# SONUÇ VERİ YAPILARI (dataclass)
# ===================================================================
# @dataclass dekoratörü, Python'a "bu sınıf sadece veri taşıyacak,
# benim için otomatik __init__, __repr__ gibi metodları üret" der.
# Bu, sonuçları düzenli ve okunabilir şekilde taşımamızı sağlar.

@dataclass
class ScopeDecision:
    """
    TEK BİR hedef için verilen kararı temsil eder.
    Her karar 4 parçadan oluşur — bu, "neden reddedildi/kabul edildi"
    sorusuna her zaman cevap verebilmemiz için önemlidir (denetlenebilirlik).
    """
    target: str        # Kullanıcının verdiği ORİJİNAL hedef (örn: "https://API.example.com:443/")
    normalized: str     # Normalize edilmiş hali (örn: "api.example.com")
    allowed: bool        # Nihai karar: True = taranabilir, False = taranamaz
    reason: str           # İnsan tarafından okunabilir açıklama: "neden bu karar verildi?"


@dataclass
class FilterResult:
    """
    ÇOKLU hedef listesi filtrelendiğinde dönen toplu sonuç.
    İki ayrı listeye bölünmüş halde tutuyoruz ki orchestrator.py
    hangi hedeflerin taranacağını (allowed) ve hangilerinin neden
    atlandığını (rejected) kolayca ayırt edebilsin.
    """
    # field(default_factory=list) kullanıyoruz çünkü dataclass'larda
    # mutable (değişebilir) varsayılan değer (örn: doğrudan =[]) TEHLİKELİDİR
    # — Python'da bu, tüm nesnelerin AYNI listeyi paylaşmasına yol açabilir.
    allowed: list[str] = field(default_factory=list)      # Taranmasına izin verilen hedefler
    rejected: list[ScopeDecision] = field(default_factory=list)  # Reddedilenler + sebepleri


# ===================================================================
# YARDIMCI FONKSİYONLAR (sınıfın dışında, bağımsız çalışan fonksiyonlar)
# ===================================================================

def _normalize_target(raw: str) -> str:
    """
    AMAÇ: Kullanıcının/aracın verdiği hedefi, her zaman TUTARLI bir
    formata çevirmek. Bunu yapmazsak aynı hedef farklı yazımlarla
    (büyük/küçük harf, port ekli/eksiz, URL'li/URL'siz) sisteme
    girip filtreyi ATLATABİLİR.

    Örnekler:
      "https://Api.Example.com:8443/path" -> "api.example.com"
      "API.EXAMPLE.COM"                    -> "api.example.com"
      "example.com."                        -> "example.com"   (sondaki nokta silinir)
      "203.0.113.10"                         -> "203.0.113.10"  (IP olduğu için değişmez)
    """
    # Baştaki/sondaki boşlukları temizle (kullanıcı yanlışlıkla
    # kopyala-yapıştırda boşluk bırakmış olabilir)
    raw = raw.strip()

    # "://" varsa bu tam bir URL demektir (http://, https:// vb.)
    if "://" in raw:
        # urlparse, URL'yi parçalarına ayırır: scheme, hostname, path, port vs.
        parsed = urlparse(raw)
        # Sadece hostname (alan adı) kısmını almak istiyoruz, path/query önemsiz.
        # Eğer bir sebeple hostname çıkarılamazsa (bozuk URL), ham veriyi kullan
        # (bu durumda muhtemelen zaten hiçbir pattern'e uymayacak ve reddedilecek,
        # bu da güvenli tarafta kalmak demek).
        host = parsed.hostname or raw
    else:
        # URL şeması yok ama yine de port olabilir: "example.com:8080"
        # ya da path olabilir: "example.com/admin"
        # Önce "/" ile ayırıp path'i at, sonra ":" ile ayırıp portu at.
        host = raw.split("/")[0].split(":")[0]

    # Sonuç olarak: küçük harfe çevir (DNS büyük/küçük harf duyarsızdır)
    # ve sondaki noktaları temizle (DNS'te "example.com." ile "example.com"
    # teknik olarak aynı şeydir — "kök" nokta gösterimi).
    return host.lower().strip(".")


def _is_ip_or_cidr(value: str) -> bool:
    """
    Verilen string bir IP adresi mi yoksa CIDR aralığı mı (örn: 203.0.113.0/24)
    kontrol eder. Bunu bilmemiz gerekiyor çünkü IP'leri ipaddress modülüyle,
    domain'leri ise fnmatch (wildcard) ile karşılaştırıyoruz — ikisi FARKLI
    eşleştirme mantıkları.

    ipaddress.ip_network() fonksiyonu, geçersiz bir IP/CIDR verilirse
    ValueError fırlatır. Biz bunu try/except ile yakalayıp basitçe
    "bu bir IP değil, o zaman domain'dir" sonucuna varıyoruz.
    """
    try:
        # strict=False: "203.0.113.10/24" gibi host bitleri sıfır olmayan
        # CIDR'lere de izin verir (bazı kullanıcılar tam IP'yi /32 olmadan yazabilir)
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


# ===================================================================
# ANA SINIF: ScopeManager
# ===================================================================

class ScopeManager:
    """
    Kullanım örneği:
        scope = ScopeManager("data/scope/my_program.yaml")
        result = scope.filter_targets(["api.example.com", "blog.example.com"])
        print(result.allowed)     # -> ["api.example.com"]
        print(result.rejected)    # -> [ScopeDecision(target="blog.example.com", ...)]
    """

    def __init__(self, program_file: str | Path):
        """
        Sınıf oluşturulduğu ANDA (nesne yaratılırken) program.yaml dosyasını
        okur ve doğrular. Eğer dosya bozuksa, HEMEN burada hata fırlatılır —
        yani "yarım hazır" bir ScopeManager nesnesi asla var olmaz.
        Bu, "sonradan patlayan" hatalar yerine "en başta patlayan" hataları
        tercih etme prensibidir (fail-fast).
        """
        # Path nesnesine çeviriyoruz — string de gelse, Path nesnesi de
        # gelse aynı şekilde çalışsın diye (esneklik).
        self.program_file = Path(program_file)

        # Dosyayı oku, doğrula, Pydantic modeline çevir.
        # Bu satır hata fırlatabilir (ScopeFileError / ScopeValidationError) —
        # bilerek try/except İLE SARMIYORUZ çünkü hatanın orchestrator.py'a
        # kadar "patlaması" (yükselmesi) istiyoruz. Sessizce yutulmamalı.
        self._program: ProgramSchema = self._load_program_file()

        # -------------------------------------------------------------
        # PERFORMANS OPTİMİZASYONU:
        # in_scope ve out_of_scope listelerini İKİYE ayırıyoruz:
        # (IP/CIDR pattern'leri) ve (domain pattern'leri).
        #
        # Neden? Çünkü her hedef sorgusunda (is_in_scope çağrısında)
        # bu ayrımı YENİDEN yapmak gereksiz iş demek. Bunun yerine
        # bir kere (nesne oluşturulurken) ayırıyoruz, sonra her
        # sorguda hazır listeleri kullanıyoruz.
        # -------------------------------------------------------------
        self._in_scope_ips, self._in_scope_domains = self._split_patterns(
            self._program.in_scope
        )
        self._out_scope_ips, self._out_scope_domains = self._split_patterns(
            self._program.out_of_scope
        )

        # Sınıf başarıyla kurulduğunda bunu logla — hangi programın
        # yüklendiği, kaç pattern olduğu görünür olsun (denetlenebilirlik).
        logger.info(
            "ScopeManager yüklendi: program='%s' | in_scope=%d | out_of_scope=%d",
            self._program.program_name,
            len(self._program.in_scope),
            len(self._program.out_of_scope),
        )

    # ------------------------------------------------------------
    # DOSYA YÜKLEME MANTIĞI
    # ------------------------------------------------------------

    def _load_program_file(self) -> ProgramSchema:
        """
        program.yaml dosyasını adım adım okur ve doğrular.
        Her adımda farklı bir hata türü olabilir, her birini ayrı
        yakalayıp ANLAMLI bir hata mesajıyla yeniden fırlatıyoruz.
        (Alt çizgi ile başlayan _load_program_file: bu metod SADECE
        sınıfın kendi içinde kullanılır, dışarıdan çağrılması beklenmez
        — Python'da "private" kabaca bu şekilde belirtilir.)
        """

        # ADIM 1: Dosya var mı?
        if not self.program_file.exists():
            raise ScopeFileError(f"Scope dosyası bulunamadı: {self.program_file}")

        # ADIM 2: Dosya okunabiliyor mu? (izin sorunu, disk hatası vs. olabilir)
        try:
            raw = self.program_file.read_text(encoding="utf-8")
        except OSError as e:
            # "from e" kullanıyoruz: orijinal hatayı (e) yeni hatamıza
            # ZİNCİRLEME olarak bağlıyoruz. Bu sayede hata ayıklarken
            # "asıl sorun neydi" bilgisini kaybetmiyoruz.
            raise ScopeFileError(f"Scope dosyası okunamadı: {e}") from e

        # ADIM 3: İçerik geçerli YAML mı? (syntax hatası olabilir,
        # örn: kapatılmamış parantez, hatalı girinti)
        try:
            data = yaml.safe_load(raw)
            # yaml.safe_load kullanıyoruz, yaml.load DEĞİL — safe_load
            # sadece güvenli/basit veri tiplerini (dict, list, str, int)
            # yükler. Normal load, YAML içine gömülü Python kodu
            # çalıştırılmasına izin verebilir — bu bir GÜVENLİK açığıdır.
            # Dış kaynaklı (veya yanlışlıkla bozulmuş) bir dosyada asla
            # yaml.load kullanılmamalı.
        except yaml.YAMLError as e:
            raise ScopeFileError(f"Scope dosyası geçersiz YAML: {e}") from e

        # ADIM 4: Dosya YAML olarak geçerli ama tamamen boşsa (örn: 0 byte)
        # yaml.safe_load None döner. Bunu ayrıca kontrol ediyoruz çünkü
        # None değeri bir sonraki adımda Pydantic'e verirsek anlaşılmaz
        # bir hata alırız.
        if data is None:
            raise ScopeFileError(f"Scope dosyası boş: {self.program_file}")

        # ADIM 5: İçerik, beklediğimiz ŞEMAYA uyuyor mu?
        # (program_name var mı, in_scope bir liste mi, vs.)
        try:
            return ProgramSchema(**data)
            # **data: dict'i "anahtar=değer" şeklinde açıp ProgramSchema'ya
            # parametre olarak veriyoruz. Pydantic burada otomatik doğrulama yapar.
        except ValidationError as e:
            raise ScopeValidationError(
                f"Scope dosyası şemaya uymuyor: {e}"
            ) from e

    @staticmethod
    def _split_patterns(patterns: list[str]) -> tuple[list[str], list[str]]:
        """
        @staticmethod: Bu fonksiyon "self" kullanmıyor, yani bir nesneye
        ihtiyacı yok. Sadece sınıfın içinde mantıksal olarak grupladığımız
        bağımsız bir yardımcı fonksiyon.

        Görevi: karışık bir pattern listesini ("*.example.com", "203.0.113.0/24",
        "api.example.com" gibi karışık halde) ikiye ayırmak:
          - IP/CIDR olanlar bir listeye
          - Domain (wildcard dahil) olanlar başka bir listeye
        """
        ips: list[str] = []
        domains: list[str] = []
        for p in patterns:
            # Her pattern'i baştan/sondan temizle, küçük harfe çevir
            # (tutarlılık için — normalize_target ile aynı kurallar).
            p_clean = p.strip().lower()
            if _is_ip_or_cidr(p_clean):
                ips.append(p_clean)
            else:
                domains.append(p_clean)
        return ips, domains

    # ------------------------------------------------------------
    # EŞLEŞTİRME MANTIĞI (asıl "beyin" burada)
    # ------------------------------------------------------------

    @staticmethod
    def _matches_domain_patterns(target: str, patterns: list[str]) -> str | None:
        """
        target (örn: "api.example.com") verilen pattern listesindeki
        HERHANGİ birine uyuyor mu diye kontrol eder.

        fnmatch.fnmatch: Unix "glob" tarzı wildcard eşleştirme yapar.
        "*" karakteri "sıfır veya daha fazla herhangi bir karakter" demektir.
        Örnek: fnmatch.fnmatch("api.example.com", "*.example.com") -> True

        Döndürdüğü değer: eşleşen İLK pattern (hangi kurala göre
        karar verildiğini açıklamak için — "reason" alanında kullanılacak).
        Hiçbiri eşleşmezse None döner.
        """
        for pattern in patterns:
            if fnmatch.fnmatch(target, pattern):
                return pattern
        return None

    @staticmethod
    def _matches_ip_patterns(target: str, patterns: list[str]) -> str | None:
        """
        target bir IP adresiyse, verilen IP/CIDR pattern listesiyle
        eşleşip eşleşmediğini kontrol eder.

        ÖNEMLİ: target önce geçerli bir IP adresine çevrilmeye çalışılır
        (ipaddress.ip_address). Eğer target aslında bir domain ise
        (örn: "api.example.com"), bu satır ValueError fırlatır ve
        biz bunu yakalayıp "bu bir IP değil, dolayısıyla IP pattern'leriyle
        eşleşmesi anlamsız" deyip None döneriz — domain eşleştirmesi
        ayrı bir fonksiyonda (_matches_domain_patterns) yapılır zaten.
        """
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            # target bir IP adresi değil (muhtemelen bir domain), bu
            # fonksiyonun işi değil — None dönüp çık.
            return None

        for pattern in patterns:
            try:
                # ip_network: "203.0.113.0/24" gibi bir aralığı nesneye çevirir.
                # strict=False: host bitleri sıfır olmasa da hata vermesin
                # (örn: kullanıcı "203.0.113.10/24" yazmış olabilir, biz
                # yine de aralığı doğru yorumlamak istiyoruz).
                network = ipaddress.ip_network(pattern, strict=False)
                # "in" operatörü, IP'nin bu ağ aralığının İÇİNDE olup
                # olmadığını kontrol eder (ipaddress modülünün kendi
                # operatör aşırı yüklemesi sayesinde).
                if target_ip in network:
                    return pattern
            except ValueError:
                # Bu pattern hiç geçerli bir IP/CIDR değilse (olmaması
                # gerekir çünkü _split_patterns'te zaten ayrıştırdık,
                # ama savunmacı programlama gereği yine de kontrol ediyoruz)
                # bu pattern'i atla, diğerlerine devam et.
                continue
        return None

    def _find_match(
        self, target: str, ip_patterns: list[str], domain_patterns: list[str]
    ) -> str | None:
        """
        Hem IP hem domain pattern'lerini tek bir çağrıda kontrol eden
        birleştirici (wrapper) fonksiyon. Önce IP kontrolü yapılır
        (çünkü hızlıdır ve target genelde ya IP ya domain'dir, ikisi
        birden olamaz), sonra domain kontrolü yapılır.
        """
        ip_match = self._matches_ip_patterns(target, ip_patterns)
        if ip_match:
            return ip_match
        return self._matches_domain_patterns(target, domain_patterns)

    # ------------------------------------------------------------
    # DIŞARIYA AÇIK (PUBLIC) API — orchestrator.py bunları çağıracak
    # ------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """
        Basit kullanım için: sadece True/False cevabı ister misin?
        Bu fonksiyon tam olarak bunu yapar. Detaylı SEBEP istiyorsan
        (neden kabul/red edildi), onun yerine evaluate() kullan.
        """
        return self.evaluate(target).allowed

    def evaluate(self, raw_target: str) -> ScopeDecision:
        """
        ASIL KARAR MEKANİZMASI BURADA.
        Tek bir hedefi alır, yukarıda anlatılan 3 ADIMLI mantığı uygular,
        ve SEBEBİYLE BİRLİKTE bir ScopeDecision nesnesi döner.

        Bu fonksiyon, sınıfın "kalbi"dir — filter_targets() de aslında
        bu fonksiyonu her hedef için tekrar tekrar çağırır.
        """
        # Önce hedefi normalize et — tutarlı karşılaştırma için şart.
        target = _normalize_target(raw_target)

        # --- ADIM 1: out_of_scope kontrolü (HER ZAMAN ÖNCE bakılır) ---
        # Neden önce bu kontrol ediliyor? Çünkü out_of_scope, in_scope'tan
        # DAHA GÜÇLÜ bir kuraldır. "Genel olarak *.example.com'a izin var
        # AMA internal.example.com'a KESİNLİKLE DOKUNMA" gibi istisna
        # durumlarını doğru işlemek için bu sıralama zorunludur.
        out_match = self._find_match(
            target, self._out_scope_ips, self._out_scope_domains
        )
        if out_match:
            # Eşleşme bulundu -> hemen reddet, in_scope'a hiç bakmaya
            # gerek yok (out_of_scope zaten kazandı).
            return ScopeDecision(
                target=raw_target,          # kullanıcının orijinal girdisi (log/debug için faydalı)
                normalized=target,           # normalize edilmiş hali
                allowed=False,                # KARAR: reddedildi
                reason=f"out_of_scope pattern'e uyuyor: '{out_match}'",  # NEDEN reddedildiği
            )

        # --- ADIM 2: in_scope kontrolü ---
        # Buraya geldiysek, hedef out_of_scope'ta DEĞİL demektir.
        # Şimdi in_scope listesinde var mı diye bakıyoruz.
        in_match = self._find_match(
            target, self._in_scope_ips, self._in_scope_domains
        )
        if in_match:
            return ScopeDecision(
                target=raw_target,
                normalized=target,
                allowed=True,                 # KARAR: kabul edildi
                reason=f"in_scope pattern'e uyuyor: '{in_match}'",
            )

        # --- ADIM 3: Hiçbir listeye uymuyor ---
        # WHITELIST MANTIĞININ KALBİ TAM BURASI:
        # Hedef ne out_of_scope'ta ne de in_scope'ta geçiyor.
        # "Belki zararsızdır, izin verelim" DEMİYORUZ.
        # Varsayılan davranış her zaman REDDETMEKTİR.
        return ScopeDecision(
            target=raw_target,
            normalized=target,
            allowed=False,
            reason="hiçbir in_scope pattern'e uymuyor (varsayılan red)",
        )

    def filter_targets(self, targets: list[str]) -> FilterResult:
        """
        Tek tek hedef sormak yerine, TOPLU bir hedef listesi
        (örneğin Subfinder'ın bulduğu 50 subdomain) verildiğinde
        bunları otomatik olarak ikiye ayırır: taranabilir olanlar
        ve reddedilenler (sebepleriyle birlikte).

        Bu fonksiyon orchestrator.py'ın ana giriş noktasıdır —
        gerçek tarama başlamadan HER ZAMAN önce bu çağrılmalıdır.
        """
        result = FilterResult()  # Boş sonuç nesnesi oluştur

        for raw in targets:
            # Her hedef için tek tek karar ver (yukarıdaki evaluate() mantığı)
            decision = self.evaluate(raw)

            if decision.allowed:
                # Kabul edildiyse: sade hedef ismini "allowed" listesine ekle
                result.allowed.append(raw)
                # DEBUG seviyesinde logla (normalde ekranda görünmez,
                # detaylı hata ayıklama modunda görünür — çok fazla
                # "kabul edildi" mesajıyla ekranı doldurmamak için)
                logger.debug("KABUL: %s (%s)", raw, decision.reason)
            else:
                # Reddedildiyse: TÜM ScopeDecision nesnesini (sebebiyle
                # birlikte) "rejected" listesine ekle.
                result.rejected.append(decision)
                # WARNING seviyesinde logla — red kararları normal
                # çalışma sırasında görünür olmalı, çünkü bunlar
                # dikkat edilmesi gereken durumlardır (örn: "neden
                # bu hedef atlandı?" sorusuna cevap verir).
                logger.warning("RED: %s -> %s", raw, decision.reason)

        return result

    # ------------------------------------------------------------
    # GELİŞTİRME/TANILAMA YARDIMCISI (opsiyonel, debug için kullanışlı)
    # ------------------------------------------------------------

    def summary(self) -> str:
        """
        Yüklü scope kurallarının okunabilir bir özetini döner.
        Terminalde "bu ScopeManager şu anda hangi kurallarla çalışıyor?"
        diye hızlıca kontrol etmek istediğinde kullanışlı.
        Örnek kullanım: print(scope.summary())
        """
        return (
            f"Program: {self._program.program_name}\n"
            f"In-scope domain pattern'leri: {self._in_scope_domains}\n"
            f"In-scope IP/CIDR: {self._in_scope_ips}\n"
            f"Out-of-scope domain pattern'leri: {self._out_scope_domains}\n"
            f"Out-of-scope IP/CIDR: {self._out_scope_ips}"
        )