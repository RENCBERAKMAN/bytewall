"""
tests/unit/test_analyzer.py
"""

from unittest.mock import MagicMock

import pytest

from ai.analyzer import analyze_findings, sort_by_priority, _extract_json
from ai.ollama_client import OllamaConnectionError
from parsers.schema import Finding, Severity


def make_finding(severity: Severity, fid: str = "1") -> Finding:
    return Finding(
        id=fid,
        source_tool="nmap",
        target="127.0.0.1",
        title=f"Test bulgu {fid}",
        description="test açıklama",
        severity=severity,
    )


# ------------------------------------------------------------
# _extract_json — hataya dayanıklı JSON çıkarma
# ------------------------------------------------------------

def test_extract_clean_json():
    result = _extract_json('{"summary": "x", "false_positive": false}')
    assert result == {"summary": "x", "false_positive": False}


def test_extract_json_from_markdown_fence():
    text = '```json\n{"summary": "x", "false_positive": true}\n```'
    result = _extract_json(text)
    assert result["false_positive"] is True


def test_extract_json_with_surrounding_text():
    text = 'İşte cevabım: {"summary": "x", "false_positive": false} umarım yeterlidir.'
    result = _extract_json(text)
    assert result["summary"] == "x"


def test_extract_json_raises_on_no_json():
    with pytest.raises(ValueError):
        _extract_json("bu metinde hiç json yok")


# ------------------------------------------------------------
# analyze_findings — başarı senaryosu
# ------------------------------------------------------------

def test_analyze_findings_populates_fields():
    findings = [make_finding(Severity.INFO)]
    mock_client = MagicMock()
    mock_client.generate.return_value = '{"summary": "risk yok", "false_positive": true}'

    result = analyze_findings(findings, client=mock_client)

    assert result[0].ai_summary == "risk yok"
    assert result[0].false_positive is True
    mock_client.generate.assert_called_once()


# ------------------------------------------------------------
# Hata izolasyonu — KRİTİK: bir bulgunun analizi başarısız olsa
# bile diğerleri etkilenmemeli, tüm işlem çökmemeli
# ------------------------------------------------------------

def test_ollama_connection_error_does_not_crash_whole_batch():
    findings = [make_finding(Severity.HIGH, "1"), make_finding(Severity.LOW, "2")]
    mock_client = MagicMock()
    mock_client.generate.side_effect = OllamaConnectionError("bağlanılamadı")

    result = analyze_findings(findings, client=mock_client)

    # İşlem çökmedi, bulgular hâlâ listede, sadece analiz edilmemiş
    assert len(result) == 2
    assert all(f.ai_summary is None for f in result)


def test_malformed_ai_response_does_not_crash():
    findings = [make_finding(Severity.MEDIUM)]
    mock_client = MagicMock()
    mock_client.generate.return_value = "bu bir json değil, düz metin"

    result = analyze_findings(findings, client=mock_client)

    assert result[0].ai_summary is None  # parse edilemedi ama çökmedi


def test_one_finding_failure_does_not_block_others():
    """
    İlk bulgunun analizi hata verse bile, ikinci bulgu YİNE de
    analiz edilmeye çalışılmalı.
    """
    findings = [make_finding(Severity.HIGH, "1"), make_finding(Severity.LOW, "2")]
    mock_client = MagicMock()
    mock_client.generate.side_effect = [
        OllamaConnectionError("ilk çağrı başarısız"),
        '{"summary": "ikinci bulgu ok", "false_positive": false}',
    ]

    result = analyze_findings(findings, client=mock_client)

    assert result[0].ai_summary is None
    assert result[1].ai_summary == "ikinci bulgu ok"
    assert mock_client.generate.call_count == 2


# ------------------------------------------------------------
# sort_by_priority
# ------------------------------------------------------------

def test_sort_by_priority_orders_by_severity():
    findings = [
        make_finding(Severity.LOW, "1"),
        make_finding(Severity.CRITICAL, "2"),
        make_finding(Severity.INFO, "3"),
        make_finding(Severity.HIGH, "4"),
    ]
    sorted_findings = sort_by_priority(findings)
    severities = [f.severity for f in sorted_findings]
    assert severities == [Severity.CRITICAL, Severity.HIGH, Severity.LOW, Severity.INFO]


def test_sort_by_priority_puts_false_positives_last_within_same_severity():
    f1 = make_finding(Severity.HIGH, "1")
    f1.false_positive = True
    f2 = make_finding(Severity.HIGH, "2")
    f2.false_positive = False

    sorted_findings = sort_by_priority([f1, f2])

    assert sorted_findings[0].id == "2"  # false_positive olmayan önce
    assert sorted_findings[1].id == "1"


def test_sort_by_priority_does_not_delete_false_positives():
    """AI'nin false_positive işaretlemesi bulguyu SİLMEMELİ, sadece sıralamayı etkilemeli."""
    findings = [make_finding(Severity.LOW, "1")]
    findings[0].false_positive = True
    result = sort_by_priority(findings)
    assert len(result) == 1  # hâlâ listede