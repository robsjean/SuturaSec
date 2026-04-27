from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel


class AuthConfig(BaseModel):
    """Credentials passed at scan creation time — never persisted to DB."""
    login_identifier: str          # email or username
    password: str
    login_url: Optional[str] = None        # explicit login endpoint (optional)
    provided_token: Optional[str] = None   # skip auth, use this token directly


class ScanCreate(BaseModel):
    target: str
    scan_type: str          # "web" | "network" | "authenticated_web" | ...
    auth_config: Optional[AuthConfig] = None


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
    compliance_reports: Optional[Any] = None
    subdomain_results: Optional[Any] = None
    api_results: Optional[Any] = None
    osint_results: Optional[Any] = None
    auth_meta: Optional[Any] = None
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
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    compliance_score: Optional[float] = None
    compliance_grade: Optional[str] = None
    subdomain_count: Optional[int] = None
    api_endpoint_count: Optional[int] = None
    osint_finding_count: Optional[int] = None

    model_config = {"from_attributes": True}
