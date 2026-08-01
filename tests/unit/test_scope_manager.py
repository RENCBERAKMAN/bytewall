"""
tests/unit/test_scope_manager.py

Bu proje için EN KRİTİK test dosyası. Scope filtrelemesi yanlış
çalışırsa gerçek dünyada bounty programı kural ihlaline yol açar.
Her yeni özellik/pattern tipi eklendiğinde buraya test eklenmeli.
"""

import pytest
from pathlib import Path
import yaml

from core.scope_manager import ScopeManager, ScopeFileError, ScopeValidationError


@pytest.fixture
def program_file(tmp_path: Path) -> Path:
    data = {
        "program_name": "test_program",
        "in_scope": [
            "*.example.com",
            "api.example.com",
            "203.0.113.0/24",
            "198.51.100.5",
        ],
        "out_of_scope": [
            "blog.example.com",
            "internal.example.com",
            "203.0.113.99",
        ],
        "notes": "test",
    }
    f = tmp_path / "program.yaml"
    f.write_text(yaml.dump(data), encoding="utf-8")
    return f


@pytest.fixture
def scope(program_file: Path) -> ScopeManager:
    return ScopeManager(program_file)


# ------------------------------------------------------------
# Temel wildcard eşleştirme
# ------------------------------------------------------------

def test_wildcard_subdomain_in_scope(scope: ScopeManager):
    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("sub.example.com") is True
    assert scope.is_in_scope("deep.sub.example.com") is True  # fnmatch * her şeyi kapsar


def test_exact_domain_in_scope(scope: ScopeManager):
    assert scope.is_in_scope("api.example.com") is True


def test_unrelated_domain_rejected_by_default(scope: ScopeManager):
    assert scope.is_in_scope("totally-unrelated.com") is False


# ------------------------------------------------------------
# out_of_scope her zaman kazanır
# ------------------------------------------------------------

def test_explicit_out_of_scope_rejected(scope: ScopeManager):
    # blog.example.com, *.example.com'a uysa bile out_of_scope kazanır
    assert scope.is_in_scope("blog.example.com") is False


def test_out_of_scope_beats_wildcard(scope: ScopeManager):
    decision = scope.evaluate("internal.example.com")
    assert decision.allowed is False
    assert "out_of_scope" in decision.reason


# ------------------------------------------------------------
# Whitelist / default-deny mantığı (EN KRİTİK TEST)
# ------------------------------------------------------------

def test_unlisted_target_rejected_by_default(scope: ScopeManager):
    """
    Listede olmayan hiçbir hedef, hangi sebeple olursa olsun,
    KABUL EDİLMEMELİ. Bu whitelist mantığının temelidir.
    """
    assert scope.is_in_scope("random-domain-not-in-any-list.com") is False
    assert scope.is_in_scope("evil.com") is False


def test_empty_in_scope_rejects_everything(tmp_path: Path):
    """
    Boş in_scope listesi -> ProgramSchema validator'ı hata fırlatmalı,
    sessizce 'her şeyi kabul et' davranışına düşmemeli.
    """
    data = {"program_name": "empty_test", "in_scope": [], "out_of_scope": []}
    f = tmp_path / "empty.yaml"
    f.write_text(yaml.dump(data), encoding="utf-8")

    with pytest.raises(ScopeValidationError):
        ScopeManager(f)


# ------------------------------------------------------------
# IP / CIDR desteği
# ------------------------------------------------------------

def test_ip_in_cidr_range_in_scope(scope: ScopeManager):
    assert scope.is_in_scope("203.0.113.10") is True   # 203.0.113.0/24 içinde
    assert scope.is_in_scope("203.0.113.254") is True


def test_ip_outside_cidr_rejected(scope: ScopeManager):
    assert scope.is_in_scope("203.0.114.10") is False  # aralık dışında


def test_exact_ip_in_scope(scope: ScopeManager):
    assert scope.is_in_scope("198.51.100.5") is True


def test_ip_explicitly_out_of_scope_beats_cidr(scope: ScopeManager):
    # 203.0.113.99, CIDR aralığında ama out_of_scope'ta ayrıca belirtilmiş
    assert scope.is_in_scope("203.0.113.99") is False


# ------------------------------------------------------------
# Normalizasyon (URL, büyük/küçük harf, port, trailing slash)
# ------------------------------------------------------------

def test_full_url_normalized_correctly(scope: ScopeManager):
    assert scope.is_in_scope("https://api.example.com/path?x=1") is True


def test_case_insensitive_matching(scope: ScopeManager):
    assert scope.is_in_scope("API.EXAMPLE.COM") is True


def test_port_stripped_before_matching(scope: ScopeManager):
    assert scope.is_in_scope("api.example.com:8443") is True


def test_trailing_dot_stripped(scope: ScopeManager):
    assert scope.is_in_scope("api.example.com.") is True


# ------------------------------------------------------------
# filter_targets — toplu işlem
# ------------------------------------------------------------

def test_filter_targets_separates_correctly(scope: ScopeManager):
    targets = [
        "api.example.com",       # kabul
        "blog.example.com",      # red (out_of_scope)
        "evil.com",               # red (listede yok)
        "203.0.113.10",           # kabul (CIDR)
    ]
    result = scope.filter_targets(targets)

    assert "api.example.com" in result.allowed
    assert "203.0.113.10" in result.allowed
    assert len(result.allowed) == 2
    assert len(result.rejected) == 2

    rejected_targets = [d.target for d in result.rejected]
    assert "blog.example.com" in rejected_targets
    assert "evil.com" in rejected_targets


def test_every_rejection_has_a_reason(scope: ScopeManager):
    result = scope.filter_targets(["evil.com", "blog.example.com"])
    for decision in result.rejected:
        assert decision.reason  # boş olmamalı, denetlenebilir olmalı


# ------------------------------------------------------------
# Dosya / hata durumları
# ------------------------------------------------------------

def test_missing_file_raises_scope_file_error(tmp_path: Path):
    with pytest.raises(ScopeFileError):
        ScopeManager(tmp_path / "does_not_exist.yaml")


def test_malformed_yaml_raises_scope_file_error(tmp_path: Path):
    f = tmp_path / "broken.yaml"
    f.write_text("in_scope: [unclosed list", encoding="utf-8")
    with pytest.raises(ScopeFileError):
        ScopeManager(f)


def test_missing_required_field_raises_validation_error(tmp_path: Path):
    data = {"in_scope": ["*.example.com"]}  # program_name eksik
    f = tmp_path / "invalid.yaml"
    f.write_text(yaml.dump(data), encoding="utf-8")
    with pytest.raises(ScopeValidationError):
        ScopeManager(f)