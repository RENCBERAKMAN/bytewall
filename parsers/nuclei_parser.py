"""
parsers/nuclei_parser.py

Nuclei'nin -jsonl ile ürettiği çıktıyı (her satır bağımsız bir JSON
nesnesi) alır, her satırı bir Finding'e çevirir.

Gerçek bir Nuclei JSONL satırı örneği (referans için):
{
  "template-id": "test-info-disclosure",
  "info": {
    "name": "...",
    "severity": "medium",
    "description": "...",
    "classification": {"cve-id": null, "cvss-score": 5.3}
  },
  "host": "127.0.0.1",
  "matched-at": "http://127.0.0.1:8888",
  "curl-command": "..."
}
"""

from __future__ import annotations

import json
import uuid

from parsers.schema import Finding, Severity
from core.logger import get_logger

logger = get_logger("bytewall.nuclei_parser")


class NucleiParseError(Exception):
    """JSONL çözümlenemedi — bozuk/eksik satır."""


# Nuclei'nin severity string'lerini bizim Severity enum'umuza eşleştiriyoruz.
# Nuclei'de ayrıca "unknown" da olabilir, onu INFO'ya düşürüyoruz.
_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


def _map_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.lower(), Severity.INFO)


def parse_nuclei_output(raw_jsonl: str, target: str) -> list[Finding]:
    """
    raw_jsonl: NucleiRunner.run()'dan gelen NucleiResult.raw_jsonl
    target: hangi hedef için tarandığı

    Nuclei'de her satır BAĞIMSIZ bir JSON nesnesidir (JSON Lines formatı,
    tek bir büyük JSON array DEĞİLDİR). Bu yüzden satır satır işliyoruz.
    Bozuk/boş bir satır varsa, TÜM taramayı iptal etmek yerine sadece
    o satırı atlayıp logluyoruz — bir satırın bozuk olması diğer
    bulguları kaybetmemizi gerektirmez.
    """
    if not raw_jsonl.strip():
        logger.info("Nuclei çıktısı boş (zafiyet bulunamadı): %s", target)
        return []

    findings: list[Finding] = []

    for line_num, line in enumerate(raw_jsonl.strip().splitlines(), start=1):
        line = line.strip()
        if not line:
            continue  # boş satırları sessizce atla

        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning(
                "Nuclei satır %d çözümlenemedi, atlanıyor: %s", line_num, e
            )
            continue

        info = data.get("info", {})
        classification = info.get("classification") or {}

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                source_tool="nuclei",
                target=target,
                title=info.get("name", data.get("template-id", "Bilinmeyen bulgu")),
                description=info.get("description", "") or "",
                severity=_map_severity(info.get("severity", "info")),
                cvss_score=classification.get("cvss-score"),
                cve_id=classification.get("cve-id"),
                affected_url=data.get("matched-at") or data.get("host"),
                evidence=data.get("curl-command", ""),
            )
        )

    logger.info("Nuclei parser: %d bulgu (%s)", len(findings), target)
    return findings