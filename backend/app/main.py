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

# Anti-SSRF : les scanners ne peuvent se connecter qu'à des adresses publiques
# (désactivé si ALLOW_PRIVATE_TARGETS=true, pour le développement local)
from app.core.egress import install_egress_guard
install_egress_guard()

app = FastAPI(
    title="SuturaSec API",
    description="Security as a Service — Analyse Web & Réseau",
    version="0.1.0",
)

# ── Erreurs de validation : messages en français, lisibles par l'utilisateur ──
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

_FIELD_LABELS = {
    "email": "Adresse email", "username": "Nom d'utilisateur", "password": "Mot de passe",
    "target": "Cible", "scan_type": "Type d'analyse", "login_identifier": "Identifiant de connexion",
}


def _french_validation_message(err: dict) -> str:
    loc = [str(p) for p in err.get("loc", []) if p not in ("body", "query", "path")]
    field = loc[-1] if loc else ""
    label = _FIELD_LABELS.get(field, field or "Champ")
    etype, msg, ctx = err.get("type", ""), err.get("msg", ""), err.get("ctx") or {}
    if etype == "missing":
        return f"{label} : champ obligatoire."
    if field == "email" or "email address" in msg:
        return "Adresse email invalide. Vérifiez le format (ex. nom@domaine.com)."
    if etype == "string_too_short":
        return f"{label} : au moins {ctx.get('min_length', '?')} caractères."
    if etype == "string_too_long":
        return f"{label} : au maximum {ctx.get('max_length', '?')} caractères."
    if etype in ("bool_parsing", "bool_type"):
        return f"{label} : valeur oui/non attendue."
    if etype == "value_error":
        # Nos validateurs lèvent déjà des messages en français
        return msg.removeprefix("Value error, ")
    if etype in ("string_type", "int_type", "dict_type", "model_type"):
        return f"{label} : format invalide."
    return f"{label} : valeur invalide."


@app.exception_handler(RequestValidationError)
async def _validation_handler(request, exc: RequestValidationError):
    messages = list(dict.fromkeys(_french_validation_message(e) for e in exc.errors()))
    return JSONResponse(
        status_code=422,
        content={"detail": " ".join(messages), "errors": messages},
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
    t: str = "",
    db: Session = Depends(get_db),
):
    """
    Rapport imprimable, ouvert dans un nouvel onglet via un lien à portée limitée
    (?t=…) émis par POST /api/scans/{id}/report-link : valable 10 min, pour CE scan
    uniquement. Le token de session n'est jamais accepté ici, pour qu'il ne finisse
    pas dans l'historique du navigateur ou les logs.
    """
    from app.core.security import decode_token

    user = None
    error_msg = "Lien de rapport manquant. Ouvrez le rapport depuis la page de l'analyse."
    data = decode_token(t) if t else None
    if t and data is None:
        error_msg = "Ce lien de rapport a expiré. Rouvrez le rapport depuis la page de l'analyse."
    elif data is not None:
        if data.get("scope") != "report" or data.get("scan_id") != scan_id:
            error_msg = "Ce lien n'est pas valide pour ce rapport."
        else:
            try:
                user = db.query(User).filter(User.id == int(data.get("sub", 0))).first()
            except (ValueError, TypeError):
                user = None
            if not user:
                error_msg = "Utilisateur introuvable."

    if not user:
        return HTMLResponse(
            "<html><head><meta charset='utf-8'><title>Rapport indisponible — SuturaSec</title></head>"
            "<body style='font-family:system-ui;padding:2rem;max-width:500px;margin:auto'>"
            "<h2 style='color:#dc2626'>Rapport indisponible</h2>"
            f"<p style='color:#334155'>{error_msg}</p>"
            f"<a href='/scans/{scan_id}' style='color:#4f46e5'>Retour à l'analyse</a>"
            "</body></html>",
            status_code=401,
            headers={"Referrer-Policy": "no-referrer"},
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

    response = templates.TemplateResponse("report.html", {
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
    # Le lien (?t=…) ne doit pas fuiter via l'en-tête Referer (polices, CDN…)
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
def health():
    return {"status": "ok", "service": "SuturaSec API"}
