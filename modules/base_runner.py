"""
Tum tarama modullerinin uymasi gereken ortak interface
(Strategy Pattern). Yeni bir arac eklerken sadece bunu
implement etmen yeterli, orchestrator'i degistirmene gerek yok.
"""
from abc import ABC, abstractmethod


class BaseRunner(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, target: str, dry_run: bool = True) -> dict:
        """
        dry_run=True ise komutu SADECE yazdirir, calistirmaz.
        Doner: ham cikti (parser'a gidecek raw dict/str)
        """
        raise NotImplementedError
