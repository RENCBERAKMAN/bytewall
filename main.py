"""
main.py

Komut satırı giriş noktası — TÜM zinciri tek komutta birleştirir:
  hedef -> scope kontrolü -> Nmap + Nuclei -> [opsiyonel] AI analizi
        -> [opsiyonel] HTML rapor

Kullanım örnekleri:
  # Sadece dry-run, hiçbir şey çalıştırma
  python main.py --program my_program --target api.example.com --dry-run

  # Gerçek tarama, sadece terminale yazdır
  python main.py --program my_program --target api.example.com

  # Tarama + AI analizi + HTML rapor (TAM ZİNCİR)
  python main.py --program my_program --target api.example.com --ai --report data/reports/scan.html
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.orchestrator import Orchestrator
from core.scope_manager import ScopeFileError, ScopeValidationError


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ByteWall - scope-safe security scan orchestrator"
    )
    parser.add_argument(
        "--program",
        required=True,
        help="data/scope/ altındaki program dosyasının adı (uzantısız), örn: my_program",
    )
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        help="Taranacak hedef. Birden fazla hedef için --target'ı tekrar kullan.",
    )
    parser.add_argument(
        "--tools",
        default="nmap,nuclei",
        help="Çalıştırılacak araçlar, virgülle ayrılmış: nmap,nuclei (varsayılan: ikisi de)",
    )
    parser.add_argument(
        "--nmap-profile",
        default="quick",
        choices=["quick", "standard", "aggressive"],
        help="Nmap tarama profili (varsayılan: quick)",
    )
    parser.add_argument(
        "--nuclei-profile",
        default="quick",
        choices=["quick", "standard", "aggressive"],
        help="Nuclei severity profili (varsayılan: quick)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Hiçbir gerçek tarama yapma, sadece hangi hedeflerin taranacağını göster.",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Bulguları yerel Ollama modeliyle analiz et (özet + false-positive tahmini).",
    )
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="Sonuçları belirtilen yola HTML rapor olarak yaz, örn. data/reports/scan.html",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    program_file = Path("data/scope") / f"{args.program}.yaml"
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]

    try:
        orchestrator = Orchestrator(
            str(program_file),
            nmap_profile=args.nmap_profile,
            nuclei_profile=args.nuclei_profile,
            tools=tools,
        )
    except (ScopeFileError, ScopeValidationError) as e:
        print(f"HATA: Scope dosyası yüklenemedi: {e}", file=sys.stderr)
        return 1

    result = orchestrator.run(args.target, dry_run=args.dry_run)

    print()
    print(f"Kullanılan araçlar: {tools}")
    print(f"Taranan hedefler: {result.scanned_targets}")
    print(f"Reddedilen hedefler: {len(result.rejected_targets)}")
    for rejected in result.rejected_targets:
        print(f"  - {rejected.target}: {rejected.reason}")

    if args.dry_run:
        # dry-run modunda AI/rapor anlamsız — hiç bulgu yok, burada dur.
        return 0

    print(f"\nToplam bulgu: {len(result.findings)}")

    # --- OPSİYONEL: AI analizi ---
    # Bu adım importu burada, fonksiyon içinde yapıyoruz (top-level değil)
    # çünkü --ai kullanılmıyorsa Ollama'ya hiç bağlanmaya çalışmamalıyız,
    # ollama_client modülünün import edilmesi bağlantı denemesi anlamına
    # gelmiyor zaten ama mantıksal olarak "sadece gerekince yükle" prensibini
    # koruyoruz.
    if args.ai:
        from ai.analyzer import analyze_findings

        print("\nAI analizi yapılıyor (bu biraz zaman alabilir)...")
        result.findings = analyze_findings(result.findings)
        analyzed_count = sum(1 for f in result.findings if f.ai_summary is not None)
        print(f"AI analizi tamamlandı: {analyzed_count}/{len(result.findings)} bulgu analiz edildi.")

    # --- Bulguları terminale yazdır ---
    for finding in result.findings:
        cve = f" ({finding.cve_id})" if finding.cve_id else ""
        fp = " [olası false positive]" if finding.false_positive else ""
        print(f"  - [{finding.severity.value.upper()}] [{finding.source_tool}] {finding.title}{cve}{fp}")
        if finding.ai_summary:
            print(f"      AI: {finding.ai_summary}")

    if result.errors:
        print(f"\nHatalar ({len(result.errors)}):")
        for error in result.errors:
            print(f"  - {error}")

    # --- OPSİYONEL: HTML rapor ---
    if args.report:
        from reports.html_builder import build_html_report

        build_html_report(
            result.findings,
            args.report,
            program_name=args.program,
            scanned_targets=result.scanned_targets,
            rejected_targets=result.rejected_targets,
        )
        print(f"\nHTML rapor oluşturuldu: {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())