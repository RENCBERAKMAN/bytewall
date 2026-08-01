"""
core/orchestrator.py

Tüm parçaları birleştiren ana akış:
  1. ScopeManager ile hedefleri filtrele (whitelist kontrolü)
  2. İzinli her hedef için NmapRunner'ı çalıştır
  3. Ham Nmap çıktısını nmap_parser ile Finding listesine çevir
  4. Sonuçları topla, döndür

KURAL: Bu dosya, ScopeManager'dan geçmemiş hiçbir hedefi asla
bir tarama modülüne iletmez. Bu kontrol burada, kod seviyesinde
zorunludur — "hatırlarım" ile değil.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.scope_manager import ScopeManager, ScopeDecision
from modules.recon.nmap_runner import NmapRunner
from parsers.nmap_parser import parse_nmap_output
from parsers.schema import Finding
from core.logger import get_logger

logger = get_logger("bytewall.orchestrator")


@dataclass
class ScanResult:
    """Tüm tarama oturumunun sonucu — hem bulgular hem de atlanan hedefler."""
    findings: list[Finding] = field(default_factory=list)
    scanned_targets: list[str] = field(default_factory=list)
    rejected_targets: list[ScopeDecision] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # tarama sırasında oluşan hatalar


class Orchestrator:
    def __init__(self, program_file: str, nmap_profile: str = "quick"):
        # ScopeManager burada bir kere kurulur, tüm hedefler için
        # tekrar tekrar kullanılır.
        self.scope = ScopeManager(program_file)
        self.nmap_runner = NmapRunner(profile=nmap_profile)

    def run(self, targets: list[str], dry_run: bool = True) -> ScanResult:
        """
        Ana giriş noktası. dry_run=True ise hiçbir gerçek tarama
        YAPILMAZ, sadece hangi hedeflerin taranacağı gösterilir —
        bu, yanlışlıkla scope dışı bir yeri taramayı önlemenin son
        güvenlik katmanıdır: her zaman önce dry-run ile kontrol et.
        """
        result = ScanResult()

        # --- ADIM 1: Scope filtrelemesi (HER ZAMAN önce) ---
        filter_result = self.scope.filter_targets(targets)
        result.rejected_targets = filter_result.rejected

        for rejected in filter_result.rejected:
            logger.warning("ATLANDI (scope dışı): %s -> %s", rejected.target, rejected.reason)

        if not filter_result.allowed:
            logger.warning("Scope içinde hiçbir hedef kalmadı, tarama yapılmayacak.")
            return result

        # --- ADIM 2: dry-run modunda sadece göster, çalıştırma ---
        if dry_run:
            logger.info("[DRY-RUN] Taranacak hedefler: %s", filter_result.allowed)
            result.scanned_targets = filter_result.allowed
            return result

        # --- ADIM 3: Her izinli hedef için gerçek tarama ---
        for target in filter_result.allowed:
            try:
                logger.info("Taranıyor: %s", target)
                nmap_result = self.nmap_runner.run(target, dry_run=False)
                findings = parse_nmap_output(nmap_result.raw_xml, target)
                result.findings.extend(findings)
                result.scanned_targets.append(target)
            except Exception as e:
                # Tek bir hedefte hata olması, DİĞER hedeflerin taranmasını
                # engellememeli — hatayı kaydet, devam et.
                error_msg = f"{target}: {type(e).__name__}: {e}"
                logger.error("Tarama hatası: %s", error_msg)
                result.errors.append(error_msg)

        return result