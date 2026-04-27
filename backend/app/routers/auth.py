from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.database import get_db
from app.models.user import User
from app.schemas.user import Token, UserCreate, UserResponse
from app.services.auth import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ─── In-memory Rate Limiter ──────────────────────────────────────────────────
#  Keyed by  "username:ip"  to resist both credential-stuffing and brute-force.
#  For production replace with Redis + slowapi.

_attempts: dict[str, list[datetime]] = defaultdict(list)
MAX_ATTEMPTS   = 5
LOCKOUT_WINDOW = timedelta(minutes=15)


def _check_rate_limit(key: str) -> None:
    """Raise 429 if the caller has exceeded MAX_ATTEMPTS in the window."""
    cutoff = datetime.utcnow() - LOCKOUT_WINDOW
    _attempts[key] = [t for t in _attempts[key] if t > cutoff]
    if len(_attempts[key]) >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Compte temporairement bloqué suite à trop de tentatives. "
                "Réessayez dans 15 minutes."
            ),
        )


def _record_failure(key: str) -> int:
    """Record a failed attempt and return remaining attempts."""
    _attempts[key].append(datetime.utcnow())
    return max(0, MAX_ATTEMPTS - len(_attempts[key]))


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
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "0.0.0.0"
    rate_key   = f"{form_data.username.lower()}:{client_ip}"

    # ① rate-limit check (before DB hit to avoid timing oracle)
    _check_rate_limit(rate_key)

    # ② credential verification — use identical error message for both
    #    "user not found" and "wrong password" to prevent user enumeration
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        remaining = _record_failure(rate_key)
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

    # ④ success — clear attempts, issue token
    _clear_attempts(rate_key)
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user
