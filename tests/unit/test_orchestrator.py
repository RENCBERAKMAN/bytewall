"""
tests/unit/test_orchestrator.py

Orchestrator'ın hem scope kontrolünü hem de her iki aracı (Nmap +
Nuclei) doğru koordine ettiğini, birinin hata vermesinin diğerini
etkilemediğini test eder. Gerçek Nmap/Nuclei subprocess çağrılarını
mock'luyoruz.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from core.orchestrator import Orchestrator
from modules.recon.nmap_runner import NmapResult
from modules.webscan.nuclei_runner import NucleiResult


@pytest.fixture
def program_file(tmp_path: Path) -> Path:
    data = {
        "program_name": "test",
        "in_scope": ["127.0.0.1", "*.example.com"],
        "out_of_scope": ["internal.example.com"],
    }
    f = tmp_path / "program.yaml"
    f.write_text(yaml.dump(data), encoding="utf-8")
    return f


FAKE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="127.0.0.1"/><ports>
  <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>"""

FAKE_NUCLEI_JSONL = '{"template-id":"t","info":{"name":"Test Finding","severity":"high"},"host":"127.0.0.1","matched-at":"127.0.0.1"}'


def test_out_of_scope_target_never_reaches_runners(program_file: Path):
    """
    KRİTİK TEST: scope dışı bir hedef, Nmap/Nuclei runner'larına
    HİÇ ULAŞMAMALI. Bunu, runner'ların .run() metodunu mock'layıp
    hiç çağrılmadığını doğrulayarak kanıtlıyoruz.
    """
    orch = Orchestrator(str(program_file), tools=["nmap", "nuclei"])

    with patch.object(orch.nmap_runner, "run") as mock_nmap, \
         patch.object(orch.nuclei_runner, "run") as mock_nuclei:

        result = orch.run(["internal.example.com"], dry_run=False)

        mock_nmap.assert_not_called()
        mock_nuclei.assert_not_called()
        assert len(result.rejected_targets) == 1
        assert len(result.findings) == 0


def test_dry_run_calls_no_runners(program_file: Path):
    orch = Orchestrator(str(program_file), tools=["nmap", "nuclei"])

    with patch.object(orch.nmap_runner, "run") as mock_nmap, \
         patch.object(orch.nuclei_runner, "run") as mock_nuclei:

        orch.run(["127.0.0.1"], dry_run=True)

        mock_nmap.assert_not_called()
        mock_nuclei.assert_not_called()


def test_both_tools_run_for_in_scope_target(program_file: Path):
    orch = Orchestrator(str(program_file), tools=["nmap", "nuclei"])

    with patch.object(
        orch.nmap_runner, "run",
        return_value=NmapResult(target="127.0.0.1", command=[], raw_xml=FAKE_NMAP_XML, dry_run=False),
    ), patch.object(
        orch.nuclei_runner, "run",
        return_value=NucleiResult(target="127.0.0.1", command=[], raw_jsonl=FAKE_NUCLEI_JSONL, dry_run=False),
    ):
        result = orch.run(["127.0.0.1"], dry_run=False)

        # Nmap'ten 1, Nuclei'den 1 -> toplam 2 bulgu, birleşik listede
        assert len(result.findings) == 2
        sources = {f.source_tool for f in result.findings}
        assert sources == {"nmap", "nuclei"}
        assert "127.0.0.1" in result.scanned_targets


def test_tools_filter_only_runs_selected_tool(program_file: Path):
    """--tools nmap verilirse Nuclei HİÇ çağrılmamalı."""
    orch = Orchestrator(str(program_file), tools=["nmap"])

    with patch.object(
        orch.nmap_runner, "run",
        return_value=NmapResult(target="127.0.0.1", command=[], raw_xml=FAKE_NMAP_XML, dry_run=False),
    ) as mock_nmap, patch.object(orch.nuclei_runner, "run") as mock_nuclei:

        result = orch.run(["127.0.0.1"], dry_run=False)

        mock_nmap.assert_called_once()
        mock_nuclei.assert_not_called()
        assert all(f.source_tool == "nmap" for f in result.findings)


def test_one_tool_failing_does_not_block_the_other(program_file: Path):
    """
    KRİTİK TEST: Nuclei hata verse bile Nmap'in bulguları kaybolmamalı.
    Her araç birbirinden bağımsız değerlendirilmeli.
    """
    orch = Orchestrator(str(program_file), tools=["nmap", "nuclei"])

    with patch.object(
        orch.nmap_runner, "run",
        return_value=NmapResult(target="127.0.0.1", command=[], raw_xml=FAKE_NMAP_XML, dry_run=False),
    ), patch.object(
        orch.nuclei_runner, "run",
        side_effect=RuntimeError("nuclei çöktü"),
    ):
        result = orch.run(["127.0.0.1"], dry_run=False)

        assert len(result.findings) == 1  # sadece Nmap'in bulgusu
        assert result.findings[0].source_tool == "nmap"
        assert len(result.errors) == 1
        assert "nuclei" in result.errors[0]


def test_multiple_targets_mixed_scope(program_file: Path):
    orch = Orchestrator(str(program_file), tools=["nmap", "nuclei"])

    with patch.object(
        orch.nmap_runner, "run",
        return_value=NmapResult(target="x", command=[], raw_xml=FAKE_NMAP_XML, dry_run=False),
    ), patch.object(
        orch.nuclei_runner, "run",
        return_value=NucleiResult(target="x", command=[], raw_jsonl=FAKE_NUCLEI_JSONL, dry_run=False),
    ):
        result = orch.run(
            ["127.0.0.1", "internal.example.com", "sub.example.com"], dry_run=False
        )

        assert "127.0.0.1" in result.scanned_targets
        assert "sub.example.com" in result.scanned_targets
        assert len(result.rejected_targets) == 1
        assert result.rejected_targets[0].target == "internal.example.com"