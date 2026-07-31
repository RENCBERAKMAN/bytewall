"""
ScopeManager testleri EN KRITIK test dosyasidir.
Scope filtrelemesi yanlis calisirsa gercek dunyada
kural ihlaline yol acabilir. Yuksek kapsam ile test et.
"""
import pytest


def test_wildcard_subdomain_in_scope():
    # TODO: "*.example.com" pattern'i "api.example.com" ile eslesmeli
    pass


def test_explicit_out_of_scope_rejected():
    # TODO: out_of_scope listesindeki bir hedef reddedilmeli
    pass


def test_unlisted_target_rejected_by_default():
    # TODO: WHITELIST mantigi - listede olmayan hedef
    # OTOMATIK OLARAK reddedilmeli (blacklist degil!)
    pass
