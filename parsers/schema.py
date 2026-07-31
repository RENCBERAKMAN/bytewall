"""
Ortak Finding modeli. Her aracin ciktisi ne olursa olsun
(XML, JSON, duz metin), parser'lar bunu bu standart yapiya
cevirir. AI katmani ve rapor katmani SADECE bu formatla calisir.

Bu, sistemin en kritik mimari kararidir - once burayi netlestir.
"""
from pydantic import BaseModel
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str                          # benzersiz kimlik (uuid)
    source_tool: str                 # "nmap", "nuclei", "zap" vs.
    target: str                      # hangi hedefte bulundu
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    affected_url: Optional[str] = None
    evidence: Optional[str] = None   # ham kanit (kisa)
    remediation: Optional[str] = None
    ai_summary: Optional[str] = None # AI katmani doldurur
    false_positive: bool = False
