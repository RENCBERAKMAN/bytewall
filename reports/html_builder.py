"""Finding listesinden HTML rapor uretir."""
from parsers.schema import Finding


def build_html_report(findings: list[Finding], output_path: str) -> None:
    # TODO: jinja2 template ile reports/templates/report.html.j2 kullan
    raise NotImplementedError
