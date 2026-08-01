"""
tests/unit/test_nuclei_runner.py

subprocess çağrılarını mock'luyoruz — gerçek Nuclei kurulu olmasa
bile, ağ bağlantısı olmasa bile testler çalışır ve hızlıdır.
"""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from modules.webscan.nuclei_runner import (
    NucleiRunner,
    NucleiNotInstalledError,
    NucleiExecutionError,
    NucleiTimeoutError,
)


@pytest.fixture
def runner() -> NucleiRunner:
    return NucleiRunner(profile="quick", timeout=30)


def test_invalid_profile_raises_value_error():
    with pytest.raises(ValueError):
        NucleiRunner(profile="does_not_exist")


def test_valid_profiles_accepted():
    for profile in ("quick", "standard", "aggressive"):
        NucleiRunner(profile=profile)


def test_dry_run_does_not_call_subprocess(runner: NucleiRunner):
    with patch("subprocess.run") as mock_run:
        result = runner.run("http://example.com", dry_run=True)

        mock_run.assert_not_called()
        assert result.dry_run is True
        assert result.raw_jsonl == ""
        assert "nuclei" in result.command


def test_dry_run_command_uses_correct_severity_flags():
    runner = NucleiRunner(profile="standard")
    result = runner.run("http://example.com", dry_run=True)
    assert "-severity" in result.command
    assert "medium,high,critical" in result.command


def test_command_never_uses_shell_true(runner: NucleiRunner):
    mock_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        runner.run("http://example.com", dry_run=False)
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell", False) is False


def test_successful_run_returns_jsonl(runner: NucleiRunner):
    fake_jsonl = '{"template-id": "test", "info": {"severity": "info"}}'
    mock_result = MagicMock(returncode=0, stdout=fake_jsonl, stderr="")

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        result = runner.run("http://example.com", dry_run=False)

        mock_run.assert_called_once()
        assert result.raw_jsonl == fake_jsonl
        assert result.returncode == 0


def test_no_findings_is_not_an_error(runner: NucleiRunner):
    """Bulgu bulunamaması (boş stdout) bir HATA değildir, returncode=0 olmalı."""
    mock_result = MagicMock(returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=mock_result):
        result = runner.run("http://example.com", dry_run=False)
        assert result.raw_jsonl == ""
        assert result.returncode == 0


def test_nuclei_not_installed_raises_custom_error(runner: NucleiRunner):
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(NucleiNotInstalledError):
            runner.run("http://example.com", dry_run=False)


def test_timeout_raises_custom_error(runner: NucleiRunner):
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=30),
    ):
        with pytest.raises(NucleiTimeoutError):
            runner.run("http://example.com", dry_run=False)


def test_nonzero_returncode_raises_execution_error(runner: NucleiRunner):
    mock_result = MagicMock(returncode=1, stdout="", stderr="connection failed")
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(NucleiExecutionError):
            runner.run("http://invalid-target", dry_run=False)