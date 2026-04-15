from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel


class ScanCreate(BaseModel):
    target: str
    scan_type: str  # "web" | "network"


class VulnerabilityResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    cvss_score: Optional[float]
    category: Optional[str]
    evidence: Optional[str]
    remediation: Optional[str]
    attack_techniques: Optional[Any] = None
    discovered_at: datetime

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    risk_score: Optional[float]
    summary: Optional[str]
    attack_paths: Optional[Any]
    threat_intel: Optional[Any] = None
    created_at: datetime
    completed_at: Optional[datetime]
    vulnerabilities: List[VulnerabilityResponse] = []

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    risk_score: Optional[float]
    created_at: datetime
    completed_at: Optional[datetime]
    vuln_count: int = 0

    model_config = {"from_attributes": True}
