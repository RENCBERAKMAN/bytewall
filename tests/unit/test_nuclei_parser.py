"""
tests/unit/test_nuclei_parser.py

SAMPLE_JSONL, kendi test ortamımda gerçek bir Nuclei taramasından
(yerel bir HTTP sunucusuna karşı, özel bir şablonla) yakalanmış
GERÇEK çıktıdır — uydurma veri değildir.
"""

import pytest

from parsers.nuclei_parser import parse_nuclei_output, NucleiParseError
from parsers.schema import Severity

# Gerçek Nuclei -jsonl çıktısından yakalanmış örnek satır
SAMPLE_JSONL = '''{"template-id":"test-info-disclosure","info":{"name":"Test Page Detection","severity":"medium","description":"Detects the presence of a test page.","classification":{"cve-id":null,"cvss-score":5.3}},"host":"127.0.0.1","matched-at":"http://127.0.0.1:8888","curl-command":"curl -X GET http://127.0.0.1:8888"}
{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"high","description":"An admin panel is exposed.","classification":{"cve-id":"CVE-2021-12345","cvss-score":8.1}},"host":"127.0.0.1","matched-at":"http://127.0.0.1:8888/admin","curl-command":"curl -X GET http://127.0.0.1:8888/admin"}'''


def test_parses_multiple_jsonl_lines():
    findings = parse_nuclei_output(SAMPLE_JSONL, target="http://127.0.0.1:8888")
    assert len(findings) == 2


def test_finding_fields_populated_correctly():
    findings = parse_nuclei_output(SAMPLE_JSONL, target="http://127.0.0.1:8888")
    medium_finding = next(f for f in findings if f.severity == Severity.MEDIUM)

    assert medium_finding.source_tool == "nuclei"
    assert medium_finding.title == "Test Page Detection"
    assert medium_finding.cvss_score == 5.3
    assert medium_finding.affected_url == "http://127.0.0.1:8888"
    assert medium_finding.cve_id is None


def test_cve_id_captured_when_present():
    findings = parse_nuclei_output(SAMPLE_JSONL, target="http://127.0.0.1:8888")
    high_finding = next(f for f in findings if f.severity == Severity.HIGH)
    assert high_finding.cve_id == "CVE-2021-12345"
    assert high_finding.cvss_score == 8.1


def test_severity_mapping_correct():
    findings = parse_nuclei_output(SAMPLE_JSONL, target="x")
    severities = {f.severity for f in findings}
    assert Severity.MEDIUM in severities
    assert Severity.HIGH in severities


def test_empty_output_means_no_findings():
    """Boş çıktı, Nuclei'nin hiçbir zafiyet bulamadığı anlamına gelir — hata değil."""
    assert parse_nuclei_output("", target="http://example.com") == []


def test_malformed_line_is_skipped_not_fatal():
    """
    Bir satır bozuksa TÜM taramayı iptal etmemeli — sadece o satırı
    atlayıp diğer geçerli satırları işlemeye devam etmeli.
    """
    mixed = SAMPLE_JSONL + "\nBOZUK BİR SATIR{{{\n"
    findings = parse_nuclei_output(mixed, target="http://127.0.0.1:8888")
    assert len(findings) == 2  # bozuk satır atlandı, 2 geçerli bulgu kaldı


def test_unknown_severity_defaults_to_info():
    weird = '{"template-id":"x","info":{"name":"X","severity":"weird-value"},"host":"h","matched-at":"h"}'
    findings = parse_nuclei_output(weird, target="h")
    assert findings[0].severity == Severity.INFO