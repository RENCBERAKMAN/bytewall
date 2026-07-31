"""
Nuclei orkestrasyonu - sablon tabanli zafiyet tarama.
SADECE ScopeManager onayindan gecmis hedeflerde calistirilmali.
"""
from modules.base_runner import BaseRunner


class NucleiRunner(BaseRunner):
    name = "nuclei"

    def run(self, target: str, dry_run: bool = True) -> dict:
        # TODO: subprocess ile nuclei cagrisi, -jsonl ile cikti al
        raise NotImplementedError
