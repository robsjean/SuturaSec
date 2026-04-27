import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.routers import auth, scans
from app.models.scan import Scan
from app.services.auth import get_current_user
from app.models.user import User

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SuturaSec API",
    description="Security as a Service — Analyse Web & Réseau",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fichiers statiques et templates
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# ── Custom Jinja2 filters ────────────────────────────────────────────────────
from datetime import datetime as _dt

def _fmt_date(value, fmt: str = "%d/%m/%Y %H:%M") -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        try:
            value = _dt.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(fmt)

_SEV_LABELS = {
    "critical": "Critique",
    "high": "Élevé",
    "medium": "Moyen",
    "low": "Faible",
    "info": "Info",
}
def _sev_label(value: str) -> str:
    return _SEV_LABELS.get((value or "").lower(), value or "—")

def _score_color(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "#6b7280"
    if s >= 80:
        return "#16a34a"
    if s >= 60:
        return "#d97706"
    return "#dc2626"

_GRADE_COLORS = {
    "A+": "#16a34a", "A": "#16a34a",
    "B": "#65a30d",
    "C": "#d97706",
    "D": "#ea580c",
    "E": "#dc2626", "F": "#dc2626",
}
def _grade_color(grade: str) -> str:
    return _GRADE_COLORS.get((grade or "").upper(), "#6b7280")

def _status_class(code) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return ""
    if c < 300:
        return "status-ok"
    if c < 400:
        return "status-redirect"
    if c < 500:
        return "status-client-err"
    return "status-server-err"

templates.env.filters["fmt_date"]    = _fmt_date
templates.env.filters["sev_label"]   = _sev_label
templates.env.filters["score_color"] = _score_color
templates.env.filters["grade_color"] = _grade_color
templates.env.filters["status_class"] = _status_class
# ─────────────────────────────────────────────────────────────────────────────

static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(auth.router)
app.include_router(scans.router)


# Routes frontend (SPA-like, tout géré par Alpine.js côté client)
@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def page_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
def page_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
def page_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def page_scan_detail(request: Request, scan_id: int):
    return templates.TemplateResponse("scan_detail.html", {"request": request, "scan_id": scan_id})


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
def page_report(
    request: Request,
    scan_id: int,
    token: str = "",
    db: Session = Depends(get_db),
):
    """Rapport imprimable. Le token JWT est passé en query param (?token=...)."""
    from app.core.security import decode_token

    # Vérifier le token passé en query param (pour les rapports ouverts dans un nouvel onglet)
    user = None
    error_msg = "Token manquant."

    if token:
        user_data = decode_token(token)
        if user_data is not None:
            try:
                user_id = int(user_data.get("sub", 0))
                if user_id:
                    user = db.query(User).filter(User.id == user_id).first()
                    if not user:
                        error_msg = "Utilisateur introuvable."
                else:
                    error_msg = "Token invalide (sub manquant)."
            except (ValueError, TypeError) as e:
                error_msg = f"Erreur de parsing du token : {e}"
        else:
            error_msg = "Token expiré ou invalide. Reconnectez-vous et réessayez."

    print(f"[Report] scan_id={scan_id} token={'présent' if token else 'absent'} user={user}")

    if not user:
        return HTMLResponse(
            f"<html><body style='font-family:system-ui;padding:2rem;max-width:500px;margin:auto'>"
            f"<h2 style='color:#dc2626'>Accès refusé</h2>"
            f"<p style='color:#334155'>{error_msg}</p>"
            f"<a href='/login' style='color:#4f46e5'>Se reconnecter</a>"
            f"</body></html>",
            status_code=401,
        )

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    vulns = scan.vulnerabilities or []
    sev_counts = {
        "critical": sum(1 for v in vulns if v.severity == "critical"),
        "high":     sum(1 for v in vulns if v.severity == "high"),
        "medium":   sum(1 for v in vulns if v.severity == "medium"),
        "low":      sum(1 for v in vulns if v.severity == "low"),
        "info":     sum(1 for v in vulns if v.severity == "info"),
    }

    rs = scan.risk_score
    if rs is None:
        risk_label = "N/A"
    elif rs >= 7:
        risk_label = "Critique"
    elif rs >= 4:
        risk_label = "Modéré"
    else:
        risk_label = "Faible"

    _SCAN_TYPE_LABELS = {
        "web":               "Analyse Web",
        "network":           "Analyse Réseau",
        "authenticated_web": "Analyse Web Authentifiée",
        "cti":               "Cyber Threat Intelligence",
        "subdomain":         "Énumération Sous-domaines",
        "api":               "Sécurité API",
        "osint":             "Reconnaissance OSINT",
    }

    ap = scan.attack_paths or {}

    return templates.TemplateResponse("report.html", {
        "request":         request,
        "scan":            scan,
        "vulnerabilities": vulns,
        "sev_counts":      sev_counts,
        "risk_label":      risk_label,
        "scan_type_label": _SCAN_TYPE_LABELS.get(scan.scan_type, scan.scan_type),
        # AI enrichment — both names used in template
        "ai":              ap,
        "attack_paths":    ap,
        # Scan-type-specific results
        "compliance":      scan.compliance_reports or None,
        "subdomain":       scan.subdomain_results or None,
        "osint":           scan.osint_results or None,
        "threat_intel":    scan.threat_intel or None,
        "api":             scan.api_results or None,
        "generated_at":    _dt.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    })


@app.get("/health")
def health():
    return {"status": "ok", "service": "SuturaSec API"}
