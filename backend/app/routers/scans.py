from datetime import datetime
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan, Vulnerability
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanListResponse, ScanResponse
from app.services.auth import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _run_scan(scan_id: int, db_url: str):
    """Exécute le scanner réel en tâche de fond (BackgroundTasks)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.scanners.web_scanner import WebScanner, compute_risk_score, generate_summary
    from app.scanners.network_scanner import NetworkScanner
    from app.services.ai_engine import enrich_scan_with_ai
    from app.services.attack_mapping import get_attack_techniques

    connect_args = {"check_same_thread": False} if "sqlite" in db_url else {}
    engine = create_engine(db_url, connect_args=connect_args)
    DBSession = sessionmaker(bind=engine)
    db = DBSession()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()

        if scan.scan_type == "web":
            scanner = WebScanner(scan.target)
            findings = scanner.run()
        elif scan.scan_type == "network":
            scanner = NetworkScanner(scan.target)
            findings = scanner.run()
        else:
            # CTI scan
            from app.scanners.cti_scanner import CTIScanner
            from app.config import settings as cfg
            cti = CTIScanner(
                scan.target,
                abuseipdb_key=cfg.ABUSEIPDB_API_KEY,
            )
            findings, threat_intel = cti.run()
            scan.threat_intel = threat_intel

        vulns = [
            Vulnerability(
                scan_id=scan.id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                cvss_score=f.cvss_score,
                category=f.category,
                evidence=f.evidence,
                remediation=f.remediation,
                attack_techniques=get_attack_techniques(f.category),
            )
            for f in findings
        ]
        db.add_all(vulns)

        from app.config import settings
        ai_result = enrich_scan_with_ai(
            target=scan.target,
            scan_type=scan.scan_type,
            findings=findings,
            api_key=settings.ANTHROPIC_API_KEY,
        )

        scan.risk_score = compute_risk_score(findings)
        scan.summary = ai_result.get("executive_summary") or generate_summary(findings, scan.target)
        scan.attack_paths = {
            "risk_narrative": ai_result.get("risk_narrative", ""),
            "attack_paths": ai_result.get("attack_paths", []),
            "top_priorities": ai_result.get("top_priorities", []),
            "quick_wins": ai_result.get("quick_wins", []),
        }
        # Compliance analysis (web + network uniquement — pas CTI)
        if scan.scan_type in ("web", "network") and findings:
            from app.services.compliance_engine import run_compliance_analysis
            scan.compliance_reports = run_compliance_analysis(findings)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.summary = f"Erreur durant le scan : {str(e)}"
            db.commit()
    finally:
        db.close()


@router.post("", response_model=ScanResponse, status_code=201)
def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if scan_data.scan_type not in ("web", "network", "cti"):
        raise HTTPException(status_code=400, detail="scan_type doit être 'web' ou 'network'")

    scan = Scan(
        user_id=current_user.id,
        target=scan_data.target,
        scan_type=scan_data.scan_type,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.config import settings
    background_tasks.add_task(_run_scan, scan.id, settings.DATABASE_URL)

    return scan


@router.get("", response_model=List[ScanListResponse])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).all()
    result = []
    for scan in scans:
        item = ScanListResponse(
            id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            risk_score=scan.risk_score,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            vuln_count=len(scan.vulnerabilities),
        )
        result.append(item)
    return result


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    db.delete(scan)
    db.commit()
