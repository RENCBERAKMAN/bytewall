"""
modules/webscan/nuclei_runner.py

Nuclei'yi subprocess üzerinden çalıştırıp JSONL (satır satır JSON)
çıktısını döner. Nmap'ten farkı: Nmap sadece "açık port" bulur,
Nuclei ise binlerce hazır şablonla GERÇEK zafiyetleri (CVE'ler,
yanlış yapılandırmalar, exposed panel'ler) tespit eder.

ÖNEMLİ GÜVENLİK NOTU:
NmapRunner ile aynı kural geçerli — bu runner SADECE
ScopeManager.filter_targets() tarafından onaylanmış hedeflerle
çağrılmalı. Scope kontrolü orchestrator.py'ın sorumluluğu.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass

from modules.base_runner import BaseRunner
from core.logger import get_logger

logger = get_logger("bytewall.nuclei_runner")


class NucleiNotInstalledError(Exception):
    """Sistemde 'nuclei' komutu bulunamadı."""


class NucleiExecutionError(Exception):
    """Nuclei çalıştı ama hata ile sonlandı."""


class NucleiTimeoutError(Exception):
    """Nuclei belirlenen süre içinde bitmedi."""


# ------------------------------------------------------------
# Şiddet seviyesi profilleri — hangi severity'deki şablonlar çalışsın
# ------------------------------------------------------------
# Nuclei binlerce şablona sahip, hepsini her seferinde çalıştırmak
# gereksiz yavaşlık yaratır. Profil, hangi ciddiyetteki zafiyetleri
# arayacağımızı sınırlar.

NUCLEI_PROFILES: dict[str, list[str]] = {
    # Sadece hızlı/düşük riskli genel bilgi toplama şablonları
    "quick": ["-severity", "info,low"],

    # Orta ve üzeri — günlük kullanım için makul denge
    "standard": ["-severity", "medium,high,critical"],

    # Her şey — kapsamlı ama en yavaş
    "aggressive": ["-severity", "info,low,medium,high,critical"],
}

DEFAULT_TIMEOUT_SECONDS = 600  # Nuclei, Nmap'ten daha uzun sürebilir (HTTP istekleri)


@dataclass
class NucleiResult:
    """Ham Nuclei sonucu — nuclei_parser.py'a gidecek girdi."""
    target: str
    command: list[str]
    raw_jsonl: str = ""
    returncode: int = 0
    dry_run: bool = True


class NucleiRunner(BaseRunner):
    name = "nuclei"

    def __init__(self, profile: str = "quick", timeout: int = DEFAULT_TIMEOUT_SECONDS):
        if profile not in NUCLEI_PROFILES:
            raise ValueError(
                f"Bilinmeyen profil: '{profile}'. "
                f"Geçerli profiller: {list(NUCLEI_PROFILES.keys())}"
            )
        self.profile = profile
        self.timeout = timeout

    def _build_command(self, target: str) -> list[str]:
        """
        Liste olarak komut oluşturuyoruz (shell=True KULLANMIYORUZ) —
        NmapRunner'daki ile aynı güvenlik gerekçesi: shell injection
        riskini ortadan kaldırmak için.
        """
        base_args = NUCLEI_PROFILES[self.profile]
        # -jsonl: her sonucu tek satır JSON olarak stdout'a bas
        # -u: hedef URL/host
        # -silent: banner ve progress mesajlarını gizle, sadece sonuçları göster
        # -duc: her taramada otomatik güncelleme kontrolü yapmasın (hem
        #       hızlandırır hem de ağ erişimi kısıtlı ortamlarda takılmayı önler)
        return ["nuclei", "-u", target, *base_args, "-jsonl", "-silent", "-duc"]

    def run(self, target: str, dry_run: bool = True) -> NucleiResult:
        command = self._build_command(target)

        if dry_run:
            logger.info("[DRY-RUN] Çalıştırılacak komut: %s", shlex.join(command))
            return NucleiResult(
                target=target,
                command=command,
                raw_jsonl="",
                returncode=0,
                dry_run=True,
            )

        logger.info("Nuclei başlatılıyor: %s (profil=%s)", target, self.profile)

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as e:
            raise NucleiNotInstalledError(
                "nuclei komutu bulunamadı. Kurulu olduğundan ve PATH'te "
                "olduğundan emin ol."
            ) from e
        except subprocess.TimeoutExpired as e:
            raise NucleiTimeoutError(
                f"Nuclei {self.timeout} saniye içinde bitmedi: {target}"
            ) from e

        # NOT: Nuclei, hiçbir zafiyet bulunamasa bile genelde returncode=0
        # döner ("bulgu yok" bir hata değildir). returncode != 0 genelde
        # gerçek bir çalıştırma hatasını (geçersiz hedef, ağ sorunu) gösterir.
        if process.returncode != 0:
            raise NucleiExecutionError(
                f"Nuclei hata koduyla sonlandı ({process.returncode}): "
                f"{process.stderr.strip()}"
            )

        logger.info("Nuclei tamamlandı: %s", target)

        return NucleiResult(
            target=target,
            command=command,
            raw_jsonl=process.stdout,
            returncode=process.returncode,
            dry_run=False,
        )