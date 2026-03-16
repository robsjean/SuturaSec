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
    if token:
        try:
            user_data = decode_token(token)
            user_id = int(user_data.get("sub"))
            user = db.query(User).filter(User.id == user_id).first()
        except Exception:
            pass

    if not user:
        return HTMLResponse("<p>Non autorisé. <a href='/login'>Se connecter</a></p>", status_code=401)

    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    ai = scan.attack_paths or {}
    return templates.TemplateResponse("report.html", {
        "request": request,
        "scan": scan,
        "vulnerabilities": scan.vulnerabilities,
        "ai": ai,
    })


@app.get("/health")
def health():
    return {"status": "ok", "service": "SuturaSec API"}
