"""
main.py

Komut satırı giriş noktası.

Kullanım:
  python main.py --program my_program --target 127.0.0.1 --dry-run
  python main.py --program my_program --target 127.0.0.1
  python main.py --program my_program --target 127.0.0.1 --tools nmap
  python main.py --program my_program --target 127.0.0.1 --tools nmap,nuclei
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

    if not args.dry_run:
        print(f"\nToplam bulgu: {len(result.findings)}")
        for finding in result.findings:
            cve = f" ({finding.cve_id})" if finding.cve_id else ""
            print(f"  - [{finding.severity.value.upper()}] [{finding.source_tool}] {finding.title}{cve}")

        if result.errors:
            print(f"\nHatalar ({len(result.errors)}):")
            for error in result.errors:
                print(f"  - {error}")

    return 0


if __name__ == "__main__":
    sys.exit(main())