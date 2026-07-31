"""
Ana orkestrator. Akis:
  1. Hedef listesi al
  2. ScopeManager'dan gecir -> sadece in-scope hedefler kalir
  3. dry_run=True ise: ne yapilacagini yazdir, hicbir sey calistirma
  4. dry_run=False ise: modulleri sirayla calistir, sonuclari parsers/ ile normalize et
  5. Normalize edilmis Finding listesini ai/analyzer.py'a gonder
  6. reports/ ile rapor uret

KURAL: Orchestrator, ScopeManager'dan gecmemis hicbir hedefi
asla bir tarama modulune iletmez. Bu kontrol kod seviyesinde
zorunludur, "hatirlarim" ile degil.
"""

from core.scope_manager import ScopeManager


class Orchestrator:
    def __init__(self, program_file: str, dry_run: bool = True):
        self.scope = ScopeManager(program_file)
        self.dry_run = dry_run

    def run(self, targets: list[str]):
        in_scope, rejected = self.scope.filter_targets(targets)

        if rejected:
            print(f"Scope disi, atlandi: {rejected}")

        if self.dry_run:
            print(f"[DRY-RUN] Su hedefler taranacakti: {in_scope}")
            return

        # TODO: modules/ altindaki runner'lari sirayla cagir
        # TODO: parsers/ ile normalize et
        # TODO: ai/analyzer.py'a gonder
        # TODO: reports/ ile rapor uret
        raise NotImplementedError
