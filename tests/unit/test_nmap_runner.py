"""
tests/unit/test_nmap_runner.py

subprocess çağrılarını mock'luyoruz — böylece testler gerçek Nmap
kurulu olmasa bile, ağ bağlantısı olmasa bile çalışır ve hızlıdır.
"""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from modules.recon.nmap_runner import (
    NmapRunner,
    NmapNotInstalledError,
    NmapExecutionError,
    NmapTimeoutError,
)


@pytest.fixture
def runner() -> NmapRunner:
    return NmapRunner(profile="quick", timeout=30)


# ------------------------------------------------------------
# Profil doğrulama
# ------------------------------------------------------------

def test_invalid_profile_raises_value_error():
    with pytest.raises(ValueError):
        NmapRunner(profile="does_not_exist")


def test_valid_profiles_accepted():
    for profile in ("quick", "standard", "aggressive"):
        NmapRunner(profile=profile)  # hata fırlatmamalı


# ------------------------------------------------------------
# Dry-run: hiçbir subprocess çağrısı YAPILMAMALI
# ------------------------------------------------------------

def test_dry_run_does_not_call_subprocess(runner: NmapRunner):
    with patch("subprocess.run") as mock_run:
        result = runner.run("example.com", dry_run=True)

        mock_run.assert_not_called()  # KRİTİK: dry-run gerçekten hiçbir şey çalıştırmamalı
        assert result.dry_run is True
        assert result.raw_xml == ""
        assert "nmap" in result.command


def test_dry_run_command_uses_correct_profile_flags():
    runner = NmapRunner(profile="standard")
    result = runner.run("example.com", dry_run=True)
    assert "-sV" in result.command
    assert "-p-" in result.command


# ------------------------------------------------------------
# Gerçek çalıştırma yolu (subprocess mock'lanmış)
# ------------------------------------------------------------

def test_successful_run_returns_xml(runner: NmapRunner):
    fake_xml = "<nmaprun><host></host></nmaprun>"
    mock_result = MagicMock(returncode=0, stdout=fake_xml, stderr="")

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        result = runner.run("example.com", dry_run=False)

        mock_run.assert_called_once()
        assert result.raw_xml == fake_xml
        assert result.returncode == 0
        assert result.dry_run is False


def test_command_never_uses_shell_true(runner: NmapRunner):
    """
    Güvenlik testi: subprocess.run çağrısında shell=True KULLANILMAMALI.
    Aksi halde hedef string'i shell tarafından yorumlanabilir
    (shell injection riski).
    """
    mock_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        runner.run("example.com", dry_run=False)
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell", False) is False


# ------------------------------------------------------------
# Hata durumları
# ------------------------------------------------------------

def test_nmap_not_installed_raises_custom_error(runner: NmapRunner):
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(NmapNotInstalledError):
            runner.run("example.com", dry_run=False)


def test_timeout_raises_custom_error(runner: NmapRunner):
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=30),
    ):
        with pytest.raises(NmapTimeoutError):
            runner.run("example.com", dry_run=False)


def test_nonzero_returncode_raises_execution_error(runner: NmapRunner):
    mock_result = MagicMock(returncode=1, stdout="", stderr="Failed to resolve host")
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(NmapExecutionError):
            runner.run("invalid-target", dry_run=False)