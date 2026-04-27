import re
from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator


# ─── Password Policy (NIST SP 800-63B + OWASP) ──────────────────────────────
_SPECIAL = r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]"

PASSWORD_POLICY = {
    "length":   (r".{8,}",            "au moins 8 caractères"),
    "upper":    (r"[A-Z]",           "une lettre majuscule (A-Z)"),
    "lower":    (r"[a-z]",           "une lettre minuscule (a-z)"),
    "digit":    (r"[0-9]",           "un chiffre (0-9)"),
    "special":  (_SPECIAL,           "un caractère spécial (!@#$%^&*...)"),
}


def validate_password_strength(password: str) -> list[str]:
    """Return a list of unmet criteria (empty = password is valid)."""
    failures = []
    for _key, (pattern, label) in PASSWORD_POLICY.items():
        if not re.search(pattern, password):
            failures.append(label)
    return failures


# ─── Schemas ─────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Le nom d'utilisateur doit contenir au moins 3 caractères")
        if len(v) > 30:
            raise ValueError("Le nom d'utilisateur ne peut pas dépasser 30 caractères")
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError(
                "Caractères autorisés : lettres (a-z, A-Z), chiffres, _, - et ."
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        failures = validate_password_strength(v)
        if failures:
            raise ValueError(
                "Mot de passe insuffisant. Requis : " + ", ".join(failures)
            )
        return v


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: int
    username: str
