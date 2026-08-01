"""
reports/html_builder.py

Finding listesini alıp, önceliklendirilmiş, okunabilir bir HTML
rapor dosyasına yazar. Bu, projenin son halkası: kullanıcı bu
dosyayı tarayıcıda açıp taramanın sonucunu tek bakışta görür.

Rapor arayüzündeki tüm metinler İngilizce (evrensel okunabilirlik
için) — bu dosyadaki Python yorumları Türkçe kalabilir, onlar
sadece geliştirme sırasında sana yardımcı olmak için.

Tasarım kararı: Bu modül core/orchestrator.py'ı İMPORT ETMEZ —
sadece parsers/schema.py (Finding) ve ai/analyzer.py (sıralama
için) bilir. Bu, "reports" katmanının orchestrator'dan bağımsız
çalışabilmesini sağlar.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ai.analyzer import sort_by_priority
from core.scope_manager import ScopeDecision
from parsers.schema import Finding, Severity
from core.logger import get_logger

logger = get_logger("bytewall.html_builder")

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Her severity'den kaç bulgu var — raporun üst kısmındaki özet için."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def build_html_report(
    findings: list[Finding],
    output_path: str,
    program_name: str = "",
    scanned_targets: list[str] | None = None,
    rejected_targets: list[ScopeDecision] | None = None,
) -> None:
    """
    findings: rapora dahil edilecek bulgular (AI analizi yapılmış
              olabilir de olmayabilir de)
    output_path: raporun yazılacağı dosya yolu, örn. "data/reports/scan.html"
    program_name: rapor başlığında gösterilecek program adı
    scanned_targets / rejected_targets: opsiyonel özet bilgisi
    """
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    sorted_findings = sort_by_priority(findings)

    html = template.render(
        program_name=program_name or "Unknown Program",
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=sorted_findings,
        severity_counts=_severity_counts(findings),
        total_findings=len(findings),
        scanned_targets=scanned_targets or [],
        rejected_targets=rejected_targets or [],
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    logger.info("HTML rapor oluşturuldu: %s (%d bulgu)", output_path, len(findings))