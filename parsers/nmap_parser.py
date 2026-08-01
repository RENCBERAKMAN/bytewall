"""
parsers/nmap_parser.py

Nmap'in -oX ile ürettiği XML çıktısını alır, her açık port için
bir Finding nesnesi üretir. Bu, ham Nmap verisini sistemin geri
kalanının (AI katmanı, rapor katmanı) anladığı ORTAK formata çevirir.

XML yapısı özetle şöyledir:
  <nmaprun>
    <host>
      <address addr="1.2.3.4" .../>
      <ports>
        <port protocol="tcp" portid="22">
          <state state="open" .../>
          <service name="ssh" product="OpenSSH" version="8.2p1" .../>
        </port>
        ...
      </ports>
    </host>
  </nmaprun>
"""

from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET

from parsers.schema import Finding, Severity
from core.logger import get_logger

logger = get_logger("bytewall.nmap_parser")


class NmapParseError(Exception):
    """XML çözümlenemedi — bozuk/eksik çıktı."""


def parse_nmap_output(raw_xml: str, target: str) -> list[Finding]:
    """
    raw_xml: NmapRunner.run()'dan gelen NmapResult.raw_xml
    target: hangi hedef için tarandığı (Finding.target alanına yazılır)

    Döner: her açık port için bir Finding. Nmap'in kendisi bir
    "zafiyet" bulmaz, sadece açık portları/servisleri raporlar —
    bu yüzden severity varsayılan olarak INFO'dur. Gerçek risk
    değerlendirmesini AI katmanı (ai/analyzer.py) veya sonraki
    aşamada Nuclei gibi zafiyet-spesifik araçlar yapar.
    """
    if not raw_xml.strip():
        # Boş XML -> muhtemelen dry-run sonucu yanlışlıkla buraya
        # gönderilmiş, ya da Nmap hiç çıktı üretmedi.
        logger.warning("Boş XML girdisi, parse edilecek bir şey yok: %s", target)
        return []

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        raise NmapParseError(f"Nmap XML çözümlenemedi: {e}") from e

    findings: list[Finding] = []

    # Bir XML çıktısında birden fazla <host> olabilir (subnet taramasında)
    for host in root.findall("host"):
        # Hedefin gerçek IP'sini XML'den al (tarama sırasında
        # domain->IP çözümlenmiş olabilir, ikisini de tutmak faydalı)
        address_elem = host.find("address")
        resolved_ip = address_elem.get("addr") if address_elem is not None else target

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue  # bu host için port bilgisi yok (örn. host down)

        for port in ports_elem.findall("port"):
            state_elem = port.find("state")
            # Sadece "open" durumundaki portları Finding olarak kaydediyoruz.
            # "closed" veya "filtered" portlar zaten bir bulgu değil.
            if state_elem is None or state_elem.get("state") != "open":
                continue

            protocol = port.get("protocol", "unknown")
            port_id = port.get("portid", "unknown")

            service_elem = port.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""

            # Başlık ve açıklamayı okunabilir şekilde oluştur
            service_desc = f"{product} {version}".strip() or service_name
            title = f"Açık port: {port_id}/{protocol} ({service_name})"
            description = (
                f"{resolved_ip} üzerinde {port_id}/{protocol} portu açık, "
                f"çalışan servis: {service_desc}."
            )

            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    source_tool="nmap",
                    target=target,
                    title=title,
                    description=description,
                    severity=Severity.INFO,   # Nmap risk seviyesi belirlemez, sadece keşfeder
                    affected_url=f"{resolved_ip}:{port_id}",
                    evidence=f"protocol={protocol} service={service_name} product={product} version={version}",
                )
            )

    logger.info("Nmap parser: %d açık port bulundu (%s)", len(findings), target)
    return findings