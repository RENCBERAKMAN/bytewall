"""
modules/base_runner.py

Tüm tarama modüllerinin uyması gereken ortak interface
(Strategy Pattern). Yeni bir araç eklerken sadece bunu
implement etmen yeterli, orchestrator'ı değiştirmene gerek yok.
"""
from abc import ABC, abstractmethod
from typing import Any


class BaseRunner(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, target: str, dry_run: bool = True) -> Any:
        """
        dry_run=True ise komutu SADECE yazdırır/hazırlar, çalıştırmaz.
        Döner: araca özel bir "ham sonuç" nesnesi (örn. NmapResult) —
        bu nesne ilgili parser'a (parsers/) gidip Finding listesine
        çevrilir. Dönüş tipi araçtan araca değişebilir (Any), ortak
        olan tek şey: her runner aynı imzaya (target, dry_run) sahip.
        """
        raise NotImplementedError