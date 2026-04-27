import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response as FastAPIResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan, Vulnerability
from app.models.user import User
from app.schemas.scan import AuthConfig, ScanCreate, ScanListResponse, ScanResponse
from app.services.auth import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _run_scan(
    scan_id: int,
    db_url: str,
    auth_login: str = "",
    auth_password: str = "",
    auth_login_url: str = "",
    auth_token: str = "",
):
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
        elif scan.scan_type == "cti":
            from app.scanners.cti_scanner import CTIScanner
            from app.config import settings as cfg
            cti = CTIScanner(
                scan.target,
                abuseipdb_key=cfg.ABUSEIPDB_API_KEY,
            )
            findings, threat_intel = cti.run()
            scan.threat_intel = threat_intel
        elif scan.scan_type == "subdomain":
            from app.scanners.subdomain_scanner import SubdomainScanner
            sub_scanner = SubdomainScanner(scan.target)
            findings, subdomain_results = sub_scanner.run()
            scan.subdomain_results = subdomain_results
        elif scan.scan_type == "api":
            from app.scanners.api_scanner import APIScanner
            api_scanner = APIScanner(scan.target)
            findings, api_results = api_scanner.run()
            scan.api_results = api_results
        elif scan.scan_type == "authenticated_web":
            from app.scanners.auth_handler import UniversalAuthHandler
            from app.scanners.authenticated_scanner import AuthenticatedScanner
            handler = UniversalAuthHandler(
                target=scan.target,
                login_identifier=auth_login,
                password=auth_password,
                login_url=auth_login_url or None,
                provided_token=auth_token or None,
            )
            auth_session = handler.authenticate()
            scan.auth_meta = {
                "strategy": auth_session.strategy,
                "success": auth_session.success,
                "login_url_used": auth_session.login_url_used,
                "token_type": auth_session.token_type,
                "is_jwt": auth_session.is_jwt,
            }
            auth_scanner = AuthenticatedScanner(scan.target, auth_session)
            findings = auth_scanner.run()
            # Clean up HTTP client
            if auth_session.client:
                try:
                    auth_session.client.close()
                except Exception:
                    pass
        else:
            # OSINT recon
            from app.scanners.osint_scanner import OSINTScanner
            osint_scanner = OSINTScanner(scan.target)
            findings, osint_results = osint_scanner.run()
            scan.osint_results = osint_results

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
        # Compliance analysis (web, network, authenticated_web)
        if scan.scan_type in ("web", "network", "authenticated_web") and findings:
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
    VALID_TYPES = ("web", "network", "cti", "subdomain", "api", "osint", "authenticated_web")
    if scan_data.scan_type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"scan_type doit être l'un de : {', '.join(VALID_TYPES)}")

    if scan_data.scan_type == "authenticated_web":
        if not scan_data.auth_config or not scan_data.auth_config.login_identifier:
            raise HTTPException(
                status_code=400,
                detail="auth_config (login_identifier + password) requis pour un scan authentifié",
            )

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
    ac: Optional[AuthConfig] = scan_data.auth_config
    background_tasks.add_task(
        _run_scan,
        scan.id,
        settings.DATABASE_URL,
        auth_login=ac.login_identifier if ac else "",
        auth_password=ac.password if ac else "",
        auth_login_url=ac.login_url or "" if ac else "",
        auth_token=ac.provided_token or "" if ac else "",
    )

    return scan


@router.get("", response_model=List[ScanListResponse])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).all()
    result = []
    for scan in scans:
        vulns = scan.vulnerabilities
        cr = scan.compliance_reports or {}
        sr = scan.subdomain_results or {}
        ar = scan.api_results or {}
        or_ = scan.osint_results or {}
        item = ScanListResponse(
            id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            risk_score=scan.risk_score,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            vuln_count=len(vulns),
            critical_count=sum(1 for v in vulns if v.severity == "critical"),
            high_count=sum(1 for v in vulns if v.severity == "high"),
            medium_count=sum(1 for v in vulns if v.severity == "medium"),
            low_count=sum(1 for v in vulns if v.severity == "low"),
            compliance_score=cr.get("global_score"),
            compliance_grade=cr.get("global_grade"),
            subdomain_count=sr.get("total_found"),
            api_endpoint_count=ar.get("total_endpoints"),
            osint_finding_count=len(vulns) if scan.scan_type == "osint" else None,
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


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: int,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Génère et retourne le rapport PDF d'un scan terminé.

    Accepte le token JWT en query param pour permettre l'ouverture
    dans un nouvel onglet via window.open().
    """
    from app.core.security import decode_token
    from app.services.pdf_report import generate_pdf_report

    # --- Auth via query param (pour window.open) ---
    if not token:
        raise HTTPException(status_code=401, detail="Token requis")

    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token invalide")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Utilisateur invalide")

    # --- Récupération du scan ---
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Le rapport n'est disponible que pour les scans terminés")

    # --- Génération PDF ---
    pdf_bytes = generate_pdf_report(scan)

    target_clean = re.sub(r"[^a-z0-9.-]", "-", scan.target.lower())[:40]
    filename = f"suturasec-{scan.scan_type}-{target_clean}-{scan.id}.pdf"

    return FastAPIResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"},
    )
