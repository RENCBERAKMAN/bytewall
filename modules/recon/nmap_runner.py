"""
modules/recon/nmap_runner.py

Nmap'i subprocess üzerinden çalıştırıp XML çıktısını döner.
Bu dosya BaseRunner interface'ini implement eder, yani
orchestrator.py bunu diğer runner'larla (Nuclei, ZAP vs.)
AYNI şekilde çağırabilir — hangi araç olduğunu bilmesine gerek yok.

ÖNEMLİ GÜVENLİK NOTU:
Bu runner'ın SADECE ScopeManager.filter_targets() tarafından
onaylanmış hedeflerle çağrılması gerekir. Bu dosyanın kendisi
scope kontrolü YAPMAZ — o iş orchestrator.py'ın sorumluluğundadır.
Bu ayrım bilinçlidir: her modül tek bir işten sorumlu olmalı
(single responsibility) — scope kontrolü ScopeManager'ın işi,
tarama çalıştırmak NmapRunner'ın işi.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field

from modules.base_runner import BaseRunner
from core.logger import get_logger

logger = get_logger("bytewall.nmap_runner")


class NmapNotInstalledError(Exception):
    """Sistemde 'nmap' komutu bulunamadı."""


class NmapExecutionError(Exception):
    """Nmap çalıştı ama hata ile sonlandı (örn. geçersiz hedef, izin sorunu)."""


class NmapTimeoutError(Exception):
    """Nmap belirlenen süre içinde bitmedi."""


# ------------------------------------------------------------
# Tarama profilleri — her biri farklı Nmap parametre seti
# ------------------------------------------------------------
# Neden ayrı bir sabit olarak tanımlıyoruz? Çünkü profil isimlerini
# (quick/standard/aggressive) tek bir yerden yönetmek istiyoruz.
# Yeni bir profil eklemek istediğinde sadece bu sözlüğe ekleme
# yapman yeterli, kodun geri kalanını değiştirmene gerek yok.

NMAP_PROFILES: dict[str, list[str]] = {
    # -T4: zamanlama şablonu (hızlı ama gürültülü değil)
    # -F: sadece en yaygın 100 portu tara (hızlı keşif)
    "quick": ["-T4", "-F"],

    # -sV: servis/versiyon tespiti
    # -p-: tüm 65535 portu tara
    "standard": ["-T4", "-sV", "-p-"],

    # -A: OS tespiti + versiyon + script tarama + traceroute (kapsamlı ama yavaş)
    "aggressive": ["-T4", "-A", "-p-"],
}

DEFAULT_TIMEOUT_SECONDS = 300  # 5 dakika — Nmap süresiz asılı kalmasın diye üst sınır


@dataclass
class NmapResult:
    """
    Nmap çalıştırmasının ham sonucu. Bu, parser'a (nmap_parser.py)
    gidecek olan girdidir. Henüz Finding'e çevrilmemiş, ham veridir.
    """
    target: str
    command: list[str]        # gerçekte çalıştırılan komut (log/debug için)
    raw_xml: str = ""           # Nmap'in -oX ile ürettiği XML çıktısı
    returncode: int = 0
    dry_run: bool = True


class NmapRunner(BaseRunner):
    name = "nmap"

    def __init__(self, profile: str = "quick", timeout: int = DEFAULT_TIMEOUT_SECONDS):
        if profile not in NMAP_PROFILES:
            raise ValueError(
                f"Bilinmeyen profil: '{profile}'. "
                f"Geçerli profiller: {list(NMAP_PROFILES.keys())}"
            )
        self.profile = profile
        self.timeout = timeout

    # ------------------------------------------------------------
    # Komut oluşturma (çalıştırmadan önce ayrı bir metod olarak
    # tutuyoruz ki dry-run modunda da AYNI komutu gösterebilelim —
    # "ne çalıştırılacaktı" ile "ne çalıştı" arasında fark olmasın)
    # ------------------------------------------------------------

    def _build_command(self, target: str) -> list[str]:
        """
        subprocess'e liste olarak komut veriyoruz (string olarak DEĞİL).
        Bu, shell injection riskini ortadan kaldırır — hedef değeri
        ne olursa olsun (örn. içinde ';' veya '&&' geçse bile) bu
        tek bir argüman olarak Nmap'e iletilir, shell tarafından
        YORUMLANMAZ. shell=True KULLANMIYORUZ, bilerek.
        """
        base_args = NMAP_PROFILES[self.profile]
        # -oX -  => XML çıktısını dosyaya değil, doğrudan stdout'a bas
        return ["nmap", *base_args, "-oX", "-", target]

    # ------------------------------------------------------------
    # Ana giriş noktası — BaseRunner interface'inin gerektirdiği metod
    # ------------------------------------------------------------

    def run(self, target: str, dry_run: bool = True) -> NmapResult:
        command = self._build_command(target)

        if dry_run:
            # shlex.join: listeyi, terminalde kopyala-yapıştır
            # çalıştırılabilir tek bir string haline getirir —
            # kullanıcı "gerçekte ne çalışacaktı" görsün diye.
            logger.info("[DRY-RUN] Çalıştırılacak komut: %s", shlex.join(command))
            return NmapResult(
                target=target,
                command=command,
                raw_xml="",
                returncode=0,
                dry_run=True,
            )

        logger.info("Nmap başlatılıyor: %s (profil=%s)", target, self.profile)

        try:
            process = subprocess.run(
                command,
                capture_output=True,   # stdout/stderr'i yakala
                text=True,               # bytes yerine str olarak al
                timeout=self.timeout,     # süresiz asılı kalmayı engelle
                check=False,                # hata kodunu biz kontrol edeceğiz (exception fırlatma)
            )
        except FileNotFoundError as e:
            # 'nmap' komutu PATH'te bulunamadı — sistemde kurulu değil
            raise NmapNotInstalledError(
                "nmap komutu bulunamadı. Kurulu olduğundan ve PATH'te "
                "olduğundan emin ol."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise NmapTimeoutError(
                f"Nmap {self.timeout} saniye içinde bitmedi: {target}"
            ) from e

        if process.returncode != 0:
            # Nmap çalıştı ama hata kodu döndürdü (örn. hedefe ulaşılamadı,
            # izin reddedildi, geçersiz hedef formatı)
            raise NmapExecutionError(
                f"Nmap hata koduyla sonlandı ({process.returncode}): "
                f"{process.stderr.strip()}"
            )

        logger.info("Nmap tamamlandı: %s", target)

        return NmapResult(
            target=target,
            command=command,
            raw_xml=process.stdout,
            returncode=process.returncode,
            dry_run=False,
        )