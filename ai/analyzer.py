"""
Finding listesini alir, AI ile onceliklendirir/ozetler.
Girdi ve cikti SADECE parsers/schema.py::Finding formatinda olmali.
"""
from parsers.schema import Finding


def analyze_findings(findings: list[Finding]) -> list[Finding]:
    # TODO: her finding icin ai_summary doldur
    # TODO: false positive filtreleme mantigi
    # TODO: onceliklendirme (severity + cvss'e gore sirala)
    raise NotImplementedError
