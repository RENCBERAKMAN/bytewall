"""
core/orchestrator.py

Tüm parçaları birleştiren ana akış:
  1. ScopeManager ile hedefleri filtrele (whitelist kontrolü)
  2. İzinli her hedef için SIRAYLA Nmap ve Nuclei'yi çalıştır
  3. Her ikisinin ham çıktısını kendi parser'ıyla Finding listesine çevir
  4. Tüm bulguları TEK bir listede topla, döndür

KURAL: Bu dosya, ScopeManager'dan geçmemiş hiçbir hedefi asla
bir tarama modülüne iletmez.

NEDEN Nmap + Nuclei BİRLİKTE:
Nmap "hangi portlar açık, hangi servisler çalışıyor" sorusuna cevap
verir (keşif). Nuclei ise "bu hedefte bilinen bir zafiyet var mı"
sorusuna cevap verir (gerçek risk tespiti). İkisi birbirini
tamamlar — sadece Nmap yeterli değil, sadece Nuclei de yeterli değil.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.scope_manager import ScopeManager, ScopeDecision
from modules.recon.nmap_runner import NmapRunner
from modules.webscan.nuclei_runner import NucleiRunner
from parsers.nmap_parser import parse_nmap_output
from parsers.nuclei_parser import parse_nuclei_output
from parsers.schema import Finding
from core.logger import get_logger

logger = get_logger("bytewall.orchestrator")


@dataclass
class ScanResult:
    """Tüm tarama oturumunun sonucu — hem bulgular hem de atlanan hedefler."""
    findings: list[Finding] = field(default_factory=list)
    scanned_targets: list[str] = field(default_factory=list)
    rejected_targets: list[ScopeDecision] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        program_file: str,
        nmap_profile: str = "quick",
        nuclei_profile: str = "quick",
        tools: list[str] | None = None,
    ):
        """
        tools: hangi araçların çalıştırılacağı, örn. ["nmap", "nuclei"].
        None ise ikisi de çalışır (varsayılan davranış).
        """
        self.scope = ScopeManager(program_file)
        self.nmap_runner = NmapRunner(profile=nmap_profile)
        self.nuclei_runner = NucleiRunner(profile=nuclei_profile)
        self.tools = tools or ["nmap", "nuclei"]

    def run(self, targets: list[str], dry_run: bool = True) -> ScanResult:
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
            logger.info(
                "[DRY-RUN] Taranacak hedefler: %s | araçlar: %s",
                filter_result.allowed,
                self.tools,
            )
            result.scanned_targets = filter_result.allowed
            return result

        # --- ADIM 3: Her izinli hedef için, seçili her araçla tara ---
        for target in filter_result.allowed:
            target_had_success = False

            if "nmap" in self.tools:
                try:
                    logger.info("[nmap] Taranıyor: %s", target)
                    nmap_result = self.nmap_runner.run(target, dry_run=False)
                    findings = parse_nmap_output(nmap_result.raw_xml, target)
                    result.findings.extend(findings)
                    target_had_success = True
                except Exception as e:
                    error_msg = f"[nmap] {target}: {type(e).__name__}: {e}"
                    logger.error("Tarama hatası: %s", error_msg)
                    result.errors.append(error_msg)

            if "nuclei" in self.tools:
                try:
                    logger.info("[nuclei] Taranıyor: %s", target)
                    nuclei_result = self.nuclei_runner.run(target, dry_run=False)
                    findings = parse_nuclei_output(nuclei_result.raw_jsonl, target)
                    result.findings.extend(findings)
                    target_had_success = True
                except Exception as e:
                    # Nuclei'nin hata vermesi Nmap'in bulgularını GEÇERSİZ
                    # kılmaz — her araç birbirinden bağımsız değerlendirilir.
                    error_msg = f"[nuclei] {target}: {type(e).__name__}: {e}"
                    logger.error("Tarama hatası: %s", error_msg)
                    result.errors.append(error_msg)

            if target_had_success:
                result.scanned_targets.append(target)

        return result