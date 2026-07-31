"""
Nmap orkestrasyonu. Gercek komut calistirma mantigi burada
implement edilecek (subprocess ile, kullanici onayi ve
dry_run kontrolu ile).
"""
from modules.base_runner import BaseRunner


class NmapRunner(BaseRunner):
    name = "nmap"

    def run(self, target: str, dry_run: bool = True) -> dict:
        # TODO: subprocess ile nmap cagrisi, -oX ile XML cikti al
        raise NotImplementedError
