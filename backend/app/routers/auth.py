from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.database import get_db
from app.models.user import User
from app.schemas.user import Token, UserCreate, UserResponse
from app.services.auth import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ─── In-memory Rate Limiter ──────────────────────────────────────────────────
#  Deux compteurs d'échecs sur une fenêtre glissante :
#   • par compte + IP  ("acct:<identifiant>:<ip>") → bloque le brute-force d'un compte
#   • global par IP    ("ip:<ip>")                 → bloque le password spraying /
#     credential stuffing (un essai sur chacun de nombreux comptes).
#  Mémoire du process uniquement : en production multi-instances, passer à Redis + slowapi.

_attempts: dict[str, list[datetime]] = defaultdict(list)
MAX_ATTEMPTS        = 5    # échecs par compte et par IP
MAX_IP_ATTEMPTS     = 20   # échecs par IP, tous comptes confondus
LOCKOUT_WINDOW      = timedelta(minutes=15)
REMEMBER_ME_DAYS    = 30


def _client_ip(request: Request) -> str:
    """
    IP réelle du client. Derrière N proxys de confiance (Railway : 1), on lit la N-ième
    entrée en partant de la DROITE de X-Forwarded-For : c'est celle ajoutée par notre
    proxy, que le client ne peut pas falsifier (contrairement aux entrées de gauche).
    """
    from app.config import settings
    hops = settings.TRUSTED_PROXY_HOPS
    if hops > 0:
        chain = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(chain) >= hops:
            return chain[-hops]
    return request.client.host if request.client else "0.0.0.0"


def _prune(key: str) -> list[datetime]:
    cutoff = datetime.utcnow() - LOCKOUT_WINDOW
    _attempts[key] = [t for t in _attempts[key] if t > cutoff]
    if not _attempts[key]:
        _attempts.pop(key, None)   # évite que le dict grossisse indéfiniment
        return []
    return _attempts[key]


def _retry_after(key: str) -> int:
    """Secondes avant que la plus ancienne tentative sorte de la fenêtre."""
    oldest = min(_attempts[key])
    return max(1, int((oldest + LOCKOUT_WINDOW - datetime.utcnow()).total_seconds()) + 1)


def _check_rate_limit(account_key: str, ip_key: str) -> None:
    """Lève 429 si l'IP ou le couple compte/IP a dépassé son quota d'échecs."""
    if len(_prune(ip_key)) >= MAX_IP_ATTEMPTS:
        wait = _retry_after(ip_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Trop de tentatives de connexion échouées depuis votre adresse IP. "
                f"Réessayez dans {max(1, wait // 60)} minute(s)."
            ),
            headers={"Retry-After": str(wait)},
        )
    if len(_prune(account_key)) >= MAX_ATTEMPTS:
        wait = _retry_after(account_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Compte temporairement bloqué suite à trop de tentatives. "
                f"Réessayez dans {max(1, wait // 60)} minute(s)."
            ),
            headers={"Retry-After": str(wait)},
        )


def _record_failure(account_key: str, ip_key: str) -> int:
    """Enregistre un échec sur les deux compteurs ; retourne les essais restants pour le compte."""
    now = datetime.utcnow()
    _attempts[account_key].append(now)
    _attempts[ip_key].append(now)
    return max(0, MAX_ATTEMPTS - len(_attempts[account_key]))


def _clear_attempts(key: str) -> None:
    _attempts.pop(key, None)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Nom d'utilisateur déjà pris")

    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    remember: bool = Form(False),
    db: Session = Depends(get_db),
):
    client_ip   = _client_ip(request)
    account_key = f"acct:{form_data.username.strip().lower()}:{client_ip}"
    ip_key      = f"ip:{client_ip}"

    # ① rate-limit check (before DB hit to avoid timing oracle)
    _check_rate_limit(account_key, ip_key)

    # ② credential verification — use identical error message for both
    #    "user not found" and "wrong password" to prevent user enumeration
    # L'identifiant peut être le nom d'utilisateur ou l'adresse email
    identifier = form_data.username.strip()
    if "@" in identifier:
        user = db.query(User).filter(func.lower(User.email) == identifier.lower()).first()
    else:
        user = db.query(User).filter(User.username == identifier).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        remaining = _record_failure(account_key, ip_key)
        detail = "Identifiants incorrects"
        if remaining <= 2:
            detail += f" — {remaining} tentative{'s' if remaining != 1 else ''} restante{'s' if remaining != 1 else ''} avant blocage"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ③ account status check
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ce compte a été désactivé. Contactez l'administrateur.",
        )

    # ④ success — on remet à zéro le compteur du compte uniquement. Le compteur IP n'est
    #    PAS effacé : sinon un attaquant alternerait spraying et connexion à son propre
    #    compte pour remettre son quota à zéro.
    _clear_attempts(account_key)
    # « Rester connecté » : session de 30 jours, sinon durée par défaut (8 h)
    expires = timedelta(days=REMEMBER_ME_DAYS) if remember else None
    access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=expires)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user
