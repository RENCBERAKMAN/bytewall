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
    id: str
    source_tool: str
    target: str
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    affected_url: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    ai_summary: Optional[str] = None
    false_positive: bool = False