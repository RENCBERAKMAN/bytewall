"""
tests/unit/test_nmap_parser.py
"""

import pytest

from parsers.nmap_parser import parse_nmap_output, NmapParseError
from parsers.schema import Severity

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_open_ports_only():
    findings = parse_nmap_output(SAMPLE_XML, target="example.com")
    assert len(findings) == 2  # sadece "open" olan 2 port, "closed" olan port hariç


def test_finding_fields_populated_correctly():
    findings = parse_nmap_output(SAMPLE_XML, target="example.com")
    ssh_finding = next(f for f in findings if "22" in f.title)

    assert ssh_finding.source_tool == "nmap"
    assert ssh_finding.target == "example.com"
    assert ssh_finding.severity == Severity.INFO
    assert "203.0.113.10:22" == ssh_finding.affected_url
    assert "OpenSSH" in ssh_finding.evidence


def test_empty_xml_returns_empty_list():
    assert parse_nmap_output("", target="example.com") == []


def test_malformed_xml_raises_parse_error():
    with pytest.raises(NmapParseError):
        parse_nmap_output("<not><valid<xml", target="example.com")


def test_host_with_no_ports_element_does_not_crash():
    xml_no_ports = """<?xml version="1.0"?>
    <nmaprun><host><address addr="1.2.3.4"/></host></nmaprun>"""
    assert parse_nmap_output(xml_no_ports, target="1.2.3.4") == []
