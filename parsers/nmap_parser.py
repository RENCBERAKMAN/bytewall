"""Nmap XML ciktisini Finding listesine cevirir."""
from parsers.schema import Finding


def parse_nmap_output(raw_xml: str) -> list[Finding]:
    # TODO: xml.etree.ElementTree ile parse et
    raise NotImplementedError
