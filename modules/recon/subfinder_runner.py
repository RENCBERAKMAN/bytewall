"""
Subfinder orkestrasyonu - PASIF kesif, hedefe aktif istek
gondermez, DNS/kayit bazli bilgi toplar. Aktif tarama
oncesi mutlaka ScopeManager'dan gecirilmeli.
"""
from modules.base_runner import BaseRunner


class SubfinderRunner(BaseRunner):
    name = "subfinder"

    def run(self, target: str, dry_run: bool = True) -> dict:
        # TODO: subprocess ile subfinder cagrisi
        raise NotImplementedError
