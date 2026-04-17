from datetime import datetime
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)  # "web" | "network"
    status = Column(String, default="pending")  # pending | running | completed | failed
    risk_score = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)
    attack_paths = Column(JSON, nullable=True)
    threat_intel = Column(JSON, nullable=True)
    compliance_reports = Column(JSON, nullable=True)
    subdomain_results = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", backref="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False)  # critical | high | medium | low | info
    cvss_score = Column(Float, nullable=True)
    category = Column(String, nullable=True)  # OWASP category or CVE type
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    attack_techniques = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")
