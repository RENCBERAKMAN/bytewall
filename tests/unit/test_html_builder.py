"""
tests/unit/test_html_builder.py
"""

from pathlib import Path

from reports.html_builder import build_html_report
from parsers.schema import Finding, Severity
from core.scope_manager import ScopeDecision


def make_finding(severity: Severity, **kwargs) -> Finding:
    defaults = dict(
        id="1", source_tool="nmap", target="127.0.0.1",
        title="Test finding", description="test description", severity=severity,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_report_file_is_created(tmp_path: Path):
    output = tmp_path / "report.html"
    build_html_report([make_finding(Severity.HIGH)], str(output))
    assert output.exists()


def test_report_contains_finding_title(tmp_path: Path):
    output = tmp_path / "report.html"
    build_html_report(
        [make_finding(Severity.CRITICAL, title="Exposed Admin Panel")],
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "Exposed Admin Panel" in content


def test_report_creates_parent_directories(tmp_path: Path):
    """If the output path is nested and doesn't exist yet, it should be created automatically."""
    output = tmp_path / "nested" / "deep" / "report.html"
    build_html_report([make_finding(Severity.LOW)], str(output))
    assert output.exists()


def test_empty_findings_shows_empty_state(tmp_path: Path):
    output = tmp_path / "report.html"
    build_html_report([], str(output))
    content = output.read_text(encoding="utf-8")
    assert "No findings were detected" in content


def test_ai_summary_included_when_present(tmp_path: Path):
    output = tmp_path / "report.html"
    build_html_report(
        [make_finding(Severity.HIGH, ai_summary="This is a serious risk.")],
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "This is a serious risk." in content


def test_false_positive_badge_shown(tmp_path: Path):
    output = tmp_path / "report.html"
    build_html_report(
        [make_finding(Severity.LOW, false_positive=True)],
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "possible false positive" in content


def test_cve_id_rendered(tmp_path: Path):
    output = tmp_path / "report.html"
    build_html_report(
        [make_finding(Severity.HIGH, cve_id="CVE-2024-9999")],
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "CVE-2024-9999" in content


def test_findings_sorted_by_severity_in_output():
    """CRITICAL findings should appear before INFO findings in the rendered output."""
    from tempfile import NamedTemporaryFile
    findings = [
        make_finding(Severity.INFO, id="1", title="Low priority item"),
        make_finding(Severity.CRITICAL, id="2", title="High priority item"),
    ]
    with NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        path = f.name
    build_html_report(findings, path)
    content = Path(path).read_text(encoding="utf-8")
    assert content.index("High priority item") < content.index("Low priority item")


def test_rejected_targets_shown_with_reason(tmp_path: Path):
    output = tmp_path / "report.html"
    rejected = [ScopeDecision(target="evil.com", normalized="evil.com", allowed=False, reason="test out-of-scope reason")]
    build_html_report([], str(output), rejected_targets=rejected)
    content = output.read_text(encoding="utf-8")
    assert "evil.com" in content
    assert "test out-of-scope reason" in content