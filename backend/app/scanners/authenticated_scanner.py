import base64
import hashlib
import hmac
import json
import re
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.scanners.auth_handler import AuthSession
from app.scanners.web_scanner import Finding, compute_risk_score, generate_summary


# ── Constants ─────────────────────────────────────────────────────────────────

_WEAK_SECRETS = [
    "secret", "password", "12345", "qwerty", "admin", "test", "key",
    "jwt_secret", "your-256-bit-secret", "changeme", "supersecret",
    "my_secret_key", "secretkey", "jwt-secret", "mysecret", "app_secret",
    "1234567890", "abc123", "123456789", "secret123", "jwttoken",
    "your_secret_key", "CHANGE_ME", "insecure", "dev_secret", "prod_secret",
]

_ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/dashboard", "/api/admin",
    "/api/admin/users", "/api/users", "/api/v1/admin", "/management",
    "/api/management", "/superadmin", "/control", "/api/control",
    "/internal", "/api/internal", "/config", "/api/config",
    "/api/v1/users", "/api/v2/users", "/api/v1/admin/users",
]

_IDOR_PATHS = [
    "/api/users/{id}", "/api/user/{id}", "/api/profile/{id}",
    "/api/orders/{id}", "/api/order/{id}", "/api/account/{id}",
    "/api/accounts/{id}", "/api/customers/{id}", "/api/invoices/{id}",
    "/api/v1/users/{id}", "/api/v1/profile/{id}", "/api/v2/users/{id}",
    "/user/{id}", "/profile/{id}", "/account/{id}",
]

_MASS_ASSIGN = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_superuser": True,
    "permissions": ["admin"],
    "privilege": "admin",
    "group": "admin",
    "rank": "superuser",
}

_SENSITIVE_PATTERNS = {
    "Credit card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "API key": r'(?i)(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})',
    "Private key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Password in response": r'(?i)"(?:password|passwd|pwd|secret)"\s*:\s*"[^"]{4,}"',
}

_SQLI_PAYLOADS = [
    ("' OR '1'='1", "anything"),
    ("' OR 1=1--", "x"),
    ("admin'--", "x"),
    ('" OR "1"="1', "anything"),
    ("1' OR '1'='1'--", "x"),
]

_LOGIN_PATHS = [
    "/api/auth/login", "/api/login", "/login", "/auth/login",
    "/api/token", "/api/v1/auth/login", "/api/signin",
]


class AuthenticatedScanner:
    """
    Runs a full authenticated security audit against a target web application.
    Covers OWASP Top 10 checks that require a valid session.
    """

    def __init__(self, target: str, auth_session: AuthSession):
        self.target = target.rstrip("/")
        self.auth = auth_session
        self.client: httpx.Client = auth_session.client  # type: ignore[assignment]
        self.findings: list[Finding] = []

    def run(self) -> list[Finding]:
        if not self.auth.success:
            self.findings.append(Finding(
                title="Échec de l'authentification — scan partiel",
                severity="high",
                category="Authentication",
                description=(
                    f"SuturaSec n'a pas pu s'authentifier sur la cible après avoir tenté "
                    f"toutes les stratégies (HTML form, JSON API, Basic Auth). "
                    f"Erreur : {self.auth.error}"
                ),
                evidence=f"Stratégie : {self.auth.strategy}",
                remediation=(
                    "Vérifier les identifiants fournis, l'URL de login et que "
                    "l'application est accessible depuis ce réseau."
                ),
                cvss_score=7.5,
            ))
            return self.findings

        checks = [
            self._check_security_headers,
            self._check_session_security,
            self._check_jwt_security,
            self._check_broken_access_control,
            self._check_idor,
            self._check_csrf,
            self._check_sensitive_data_exposure,
            self._check_mass_assignment,
            # Le bypass SQLi passe AVANT le rate limiting : ce dernier déclenche
            # volontairement des blocages (429) qui fausseraient le test SQLi.
            self._check_auth_bypass,
            self._check_rate_limiting,
        ]
        for check in checks:
            try:
                check()
            except Exception:
                pass

        return self.findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get(self, path: str, **kw) -> Optional[httpx.Response]:
        try:
            url = path if "://" in path else self.target + path
            return self.client.get(url, **kw)
        except Exception:
            return None

    def _post(self, path: str, **kw) -> Optional[httpx.Response]:
        try:
            url = path if "://" in path else self.target + path
            return self.client.post(url, **kw)
        except Exception:
            return None

    def _add(self, f: Finding):
        self.findings.append(f)

    def _find_login_url(self) -> str:
        lu = self.auth.login_url_used
        if lu and "://" not in lu:
            lu = self.target + lu
        if lu:
            return lu
        for p in _LOGIN_PATHS:
            r = self._post(p, json={"username": "_probe_", "password": "_probe_"})
            if r and r.status_code in (200, 400, 401, 422):
                return self.target + p
        return ""

    # ── Helpers : tentatives de login dans le bon format ──────────────────────

    _LOGIN_REJECTED_RE = re.compile(
        r"invalid credentials|invalid password|wrong password|bad credentials|"
        r"authentication failed|login failed|identifiants incorrects|mot de passe incorrect|"
        r'"success"\s*:\s*false',
        re.IGNORECASE,
    )

    def _login_attempt(self, url: str, fmt: dict, identifier: str, password: str):
        """POST de login dans le format décrit par fmt = {encoding, id, pwd, extra}."""
        body = {**fmt["extra"], fmt["id"]: identifier, fmt["pwd"]: password}
        if fmt["encoding"] == "form":
            return self._post(url, data=body)
        return self._post(url, json=body)

    def _is_login_rejection(self, r) -> bool:
        """
        True si l'endpoint a compris la requête et refusé les identifiants.
        Un 400/415/422 « champ manquant / format invalide » ne compte PAS : la requête
        n'a alors jamais atteint la vérification des identifiants.
        """
        if r is None:
            return False
        if r.status_code in (401, 403, 429):
            return True
        if r.status_code in (200, 400):
            return bool(self._LOGIN_REJECTED_RE.search(r.text or ""))
        return False

    def _login_format(self, login_url: str) -> Optional[dict]:
        """
        Format de login à utiliser pour les checks. Priorité au format de la session
        obtenue ; sinon (token fourni, Basic…) on le détecte avec une tentative invalide.
        """
        if self.auth.login_encoding and self.auth.login_id_field:
            return {
                "encoding": self.auth.login_encoding,
                "id": self.auth.login_id_field,
                "pwd": self.auth.login_pwd_field or "password",
                "extra": dict(self.auth.login_extra),
            }
        for encoding in ("json", "form"):
            for id_field in ("username", "email"):
                fmt = {"encoding": encoding, "id": id_field, "pwd": "password", "extra": {}}
                probe = self._login_attempt(
                    login_url, fmt, "suturasec_format_probe@example.com", "__wrong_password__")
                if self._is_login_rejection(probe):
                    return fmt
        return None

    def _inconclusive(self, title: str, login_url: str, why: str):
        """Signale honnêtement un test non réalisé, au lieu d'un faux résultat."""
        self._add(Finding(
            title=title,
            severity="info",
            category="Couverture du scan",
            description=(
                f"Ce test n'a pas pu être réalisé sur {login_url} : {why}. "
                "Aucune conclusion ne doit en être tirée, ni positive ni négative."
            ),
            evidence=f"Endpoint : {login_url}",
            remediation="Indiquer l'URL exacte de l'endpoint de login dans la configuration du scan, puis relancer.",
            cvss_score=0.0,
        ))

    # ── Check 1: Security Headers ─────────────────────────────────────────────

    def _check_security_headers(self):
        r = self._get("/")
        if not r:
            return
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        required = {
            "Strict-Transport-Security": ("strict-transport-security",),
            "Content-Security-Policy": ("content-security-policy", "x-content-security-policy"),
            "X-Frame-Options": ("x-frame-options",),
            "X-Content-Type-Options": ("x-content-type-options",),
            "Referrer-Policy": ("referrer-policy",),
        }
        missing = [name for name, keys in required.items() if not any(k in hdrs for k in keys)]
        if missing:
            self._add(Finding(
                title="En-têtes de sécurité HTTP manquants (session authentifiée)",
                severity="medium",
                category="Security Misconfiguration",
                description=f"Absents des réponses authentifiées : {', '.join(missing)}.",
                evidence=f"Headers présents : {', '.join(hdrs.keys())}",
                remediation="Configurer HSTS, CSP, X-Frame-Options, X-Content-Type-Options et Referrer-Policy.",
                cvss_score=5.3,
            ))

        csp = hdrs.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            self._add(Finding(
                title="CSP permissive : 'unsafe-inline' détecté",
                severity="medium",
                category="Security Misconfiguration",
                description="La directive 'unsafe-inline' dans la CSP annule la protection XSS.",
                evidence=f"Content-Security-Policy: {csp[:300]}",
                remediation="Remplacer 'unsafe-inline' par des nonces ou hashes CSP.",
                cvss_score=5.0,
            ))

    # ── Check 2: Session Security ─────────────────────────────────────────────

    def _check_session_security(self):
        r = self._get("/")
        if not r:
            return
        set_cookie = r.headers.get("set-cookie", "")

        # Token in URL
        url_str = str(r.url)
        if self.auth.token and len(self.auth.token) > 10 and self.auth.token in url_str:
            self._add(Finding(
                title="Token d'authentification exposé dans l'URL",
                severity="high",
                category="Sensitive Data Exposure",
                description="Le token d'authentification est transmis via l'URL, l'exposant aux logs serveur, historique navigateur et referrer headers.",
                evidence=f"URL: {url_str[:200]}",
                remediation="Transmettre les tokens uniquement via l'en-tête Authorization ou un cookie sécurisé.",
                cvss_score=7.5,
            ))

        # Cookie security flags
        sc_lower = set_cookie.lower()
        if any(s in sc_lower for s in ("session", "auth", "token", "jwt")):
            missing_flags = []
            if "httponly" not in sc_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in sc_lower:
                missing_flags.append("Secure")
            if "samesite" not in sc_lower:
                missing_flags.append("SameSite")
            if missing_flags:
                self._add(Finding(
                    title=f"Cookie de session sans attributs : {', '.join(missing_flags)}",
                    severity="high" if "HttpOnly" in missing_flags else "medium",
                    category="Broken Authentication",
                    description=f"Les cookies d'authentification manquent : {', '.join(missing_flags)}.",
                    evidence=f"Set-Cookie: {set_cookie[:300]}",
                    remediation=f"Ajouter {', '.join(missing_flags)} à tous les cookies de session.",
                    cvss_score=6.5,
                ))

    # ── Check 3: JWT Security ─────────────────────────────────────────────────

    def _check_jwt_security(self):
        if not self.auth.is_jwt or not self.auth.token:
            return

        parts = self.auth.token.split(".")
        try:
            hdr_raw = parts[0] + "=" * (-len(parts[0]) % 4)
            hdr = json.loads(base64.urlsafe_b64decode(hdr_raw))
        except Exception:
            hdr = {}

        alg = hdr.get("alg", "").upper()

        if alg == "NONE":
            self._add(Finding(
                title="JWT avec algorithme 'none' — falsification possible",
                severity="critical",
                category="Broken Authentication",
                description="Le serveur accepte des JWT signés avec l'algorithme 'none', permettant une falsification complète sans clé.",
                evidence=f"JWT header: {json.dumps(hdr)}",
                remediation="Rejeter explicitement les JWT avec alg='none'. Valider l'algorithme côté serveur indépendamment du header.",
                cvss_score=9.8,
            ))
        elif alg in ("HS256", "HS384", "HS512"):
            digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
            dig = digest_map.get(alg, hashlib.sha256)
            header_payload = f"{parts[0]}.{parts[1]}"
            for secret in _WEAK_SECRETS:
                try:
                    sig = hmac.new(secret.encode(), header_payload.encode(), dig).digest()
                    expected = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                    if expected == parts[2]:
                        self._add(Finding(
                            title="Secret JWT HMAC faible — token forgeable",
                            severity="critical",
                            category="Broken Authentication",
                            description=f"Le secret HMAC du JWT est trivial ('{secret}'). Un attaquant peut créer des tokens arbitraires avec n'importe quel payload.",
                            evidence=f"Secret trouvé : '{secret}' | Algorithme : {alg}",
                            remediation="Remplacer le secret par une valeur aléatoire cryptographiquement sûre d'au moins 256 bits. Rotation immédiate.",
                            cvss_score=9.1,
                        ))
                        break
                except Exception:
                    pass
        elif alg == "RS256":
            self._add(Finding(
                title="JWT RS256 — vérifier la résistance à l'algorithm confusion",
                severity="info",
                category="Broken Authentication",
                description="Vérifier que le serveur rejette les tokens signés HS256 avec la clé publique RSA (algorithm confusion attack, CVE pattern).",
                evidence=f"alg: RS256",
                remediation="Valider l'algorithme attendu de manière statique côté serveur.",
                cvss_score=3.7,
            ))

        payload = self.auth.jwt_payload or {}

        # Excessive expiry
        exp = payload.get("exp")
        iat = payload.get("iat")
        if exp and iat and (exp - iat) > 86400 * 30:
            self._add(Finding(
                title="JWT avec durée de vie excessive (> 30 jours)",
                severity="medium",
                category="Broken Authentication",
                description=f"Le token est valide {(exp - iat) // 86400} jours, augmentant la fenêtre d'exploitation en cas de compromission.",
                evidence=f"iat={iat}, exp={exp}, durée={(exp - iat) // 86400}j",
                remediation="Limiter les access tokens à 15 min–1 h. Utiliser des refresh tokens.",
                cvss_score=4.3,
            ))

        # PII in payload
        pii_keys = ["password", "passwd", "secret", "ssn", "credit_card", "card_number"]
        found_pii = [k for k in pii_keys if k in payload]
        if found_pii:
            self._add(Finding(
                title="Données sensibles dans le payload JWT",
                severity="high",
                category="Sensitive Data Exposure",
                description=f"Le JWT contient des champs sensibles ({found_pii}). Le payload est lisible sans clé.",
                evidence=f"Champs : {found_pii}",
                remediation="Ne jamais stocker de données sensibles dans les claims JWT.",
                cvss_score=7.5,
            ))

    # ── Check 4: Broken Access Control ───────────────────────────────────────

    def _check_broken_access_control(self):
        _SOFT_404 = re.compile(
            r"not found|404|page not found|unauthorized|login required|access denied|forbidden|no access",
            re.IGNORECASE,
        )
        accessible = []
        for path in _ADMIN_PATHS:
            r = self._get(path)
            if not r or r.status_code not in (200, 201):
                continue
            if len(r.text) < 100:
                continue
            if "login" in str(r.url).lower():
                continue
            if _SOFT_404.search(r.text[:500]):
                continue
            # Confirmer que l'accès authentifié renvoie plus de contenu qu'un accès non-authentifié
            # Si les deux renvoient 200 avec un contenu similaire, c'est un endpoint public (pas BAC)
            try:
                unauth_r = httpx.get(self.target + path, follow_redirects=True, timeout=10, verify=False)
                if unauth_r.status_code == 200 and abs(len(unauth_r.text) - len(r.text)) < 200:
                    continue  # Endpoint public — pas une violation de contrôle d'accès
            except Exception:
                pass
            accessible.append(path)
            if len(accessible) >= 3:
                break

        if accessible:
            self._add(Finding(
                title="Routes d'administration accessibles avec un compte standard",
                severity="critical",
                category="Broken Access Control",
                description=f"Des endpoints admin/gestion retournent HTTP 200 pour un compte utilisateur normal : {accessible}",
                evidence=f"Paths accessibles (contenu différent de l'accès non-authentifié) : {accessible}",
                remediation="Implémenter RBAC strict. Vérifier les permissions à chaque requête côté serveur.",
                cvss_score=9.1,
            ))

        # Try unauthenticated access
        try:
            unauth = httpx.Client(follow_redirects=False, timeout=10, verify=False)
            open_paths = []
            for path in ["/api/users", "/api/profile", "/api/admin", "/api/v1/users", "/api/me"]:
                try:
                    r = unauth.get(self.target + path)
                    if r.status_code in (200, 201) and len(r.text) > 50:
                        # Vérifier que ce n'est pas une soft-404
                        if not _SOFT_404.search(r.text[:300]):
                            open_paths.append(path)
                except Exception:
                    pass
            unauth.close()
            if open_paths:
                self._add(Finding(
                    title="Endpoints API accessibles sans authentification",
                    severity="high",
                    category="Broken Access Control",
                    description=f"Des endpoints retournent HTTP 200 sans token d'auth : {open_paths}",
                    evidence=f"Paths sans auth : {open_paths}",
                    remediation="Toutes les routes API protégées doivent valider le token à chaque requête.",
                    cvss_score=8.1,
                ))
        except Exception:
            pass

    # ── Check 5: IDOR ─────────────────────────────────────────────────────────

    def _check_idor(self):
        # Champs PII précis — exclure "name" (trop générique, présent partout)
        _PII_KEYS = frozenset({"email", "username", "phone", "address", "ssn", "credit_card", "social_security", "date_of_birth"})
        idor_found = []

        for path_tmpl in _IDOR_PATHS[:10]:
            r_low = self._get(path_tmpl.replace("{id}", "1"))
            r_high = self._get(path_tmpl.replace("{id}", "99999"))

            for r, tid in [(r_low, 1), (r_high, 99999)]:
                if not r or r.status_code != 200 or len(r.text) < 100:
                    continue
                try:
                    data = r.json()
                    text = json.dumps(data).lower() if isinstance(data, dict) else ""
                    if not any(k in text for k in _PII_KEYS):
                        continue
                    # IDOR confirmé uniquement si deux IDs différents retournent un contenu distinct
                    if r_low and r_high and r_low.status_code == 200 and r_high.status_code == 200:
                        if r_low.text == r_high.text:
                            continue  # Même réponse pour tous les IDs — endpoint générique, pas IDOR
                    idor_found.append(path_tmpl.replace("{id}", str(tid)))
                    break
                except Exception:
                    pass

            if len(idor_found) >= 3:
                break

        if idor_found:
            self._add(Finding(
                title="IDOR — Référence directe d'objet non sécurisée",
                severity="high",
                category="Broken Access Control",
                description=f"Des ressources appartenant à d'autres utilisateurs sont accessibles par simple énumération d'ID : {idor_found[:3]}",
                evidence=f"Exemples accessibles (HTTP 200 + PII, contenu distinct par ID) : {idor_found[:3]}",
                remediation="Vérifier à chaque requête que l'utilisateur est propriétaire de la ressource. Utiliser des UUIDs non séquentiels.",
                cvss_score=8.0,
            ))

    # ── Check 6: CSRF ─────────────────────────────────────────────────────────

    def _check_csrf(self):
        evil = "https://evil.example.com"
        _NOT_PROCESSED = re.compile(
            r"not found|method not allowed|invalid|bad request|unsupported|no route",
            re.IGNORECASE,
        )
        csrf_paths = []
        for path in ["/api/profile", "/api/user", "/api/settings", "/api/v1/user", "/api/account", "/api/me"]:
            # Vérifier d'abord que l'endpoint existe (GET authentifié retourne 200)
            r_get = self._get(path)
            if not r_get or r_get.status_code != 200:
                continue  # Endpoint inexistant — ne pas le tester

            r = self._post(
                path,
                json={"test": "csrf_probe"},
                headers={"Origin": evil, "Referer": f"{evil}/attack"},
            )
            if not r or r.status_code not in (200, 201, 204):
                continue
            body = r.text.strip()
            # Éliminer les réponses vides ou qui indiquent clairement un rejet
            if r.status_code != 204 and len(body) < 10:
                continue
            if _NOT_PROCESSED.search(body[:300]):
                continue
            csrf_paths.append(path)

        if csrf_paths:
            self._add(Finding(
                title="Protection CSRF insuffisante — origine croisée acceptée",
                severity="high",
                category="Cross-Site Request Forgery",
                description=f"Des endpoints acceptent des requêtes cross-origin sans token CSRF : {csrf_paths[:3]}",
                evidence=f"POST avec Origin: {evil} → HTTP 200 sur : {csrf_paths[:3]}",
                remediation="Implémenter tokens CSRF SynchronizerToken ou Double-Submit Cookie. Valider Origin/Referer.",
                cvss_score=8.0,
            ))

        r = self._get("/")
        if r:
            sc = r.headers.get("set-cookie", "").lower()
            if any(s in sc for s in ("session", "auth", "token")) and "samesite" not in sc:
                self._add(Finding(
                    title="Cookie sans attribut SameSite — risque CSRF",
                    severity="medium",
                    category="Cross-Site Request Forgery",
                    description="Les cookies d'authentification n'ont pas SameSite, les rendant vulnérables aux attaques CSRF.",
                    evidence=f"Set-Cookie extrait: {sc[:200]}",
                    remediation="Définir SameSite=Strict ou SameSite=Lax sur les cookies de session.",
                    cvss_score=5.4,
                ))

    # ── Check 7: Sensitive Data Exposure ──────────────────────────────────────

    def _check_sensitive_data_exposure(self):
        data_paths = [
            "/api/me", "/api/user/me", "/api/profile", "/api/account",
            "/api/v1/me", "/api/users/me", "/api/auth/me",
        ]
        found: list[tuple[str, str]] = []
        hash_exposed = False
        for path in data_paths:
            r = self._get(path)
            if not r or r.status_code != 200:
                continue
            for name, pattern in _SENSITIVE_PATTERNS.items():
                if re.search(pattern, r.text):
                    found.append((path, name))
            t_low = r.text.lower()
            if not hash_exposed and any(
                k in t_low for k in ('"hashed_password"', '"password_hash"', '"passwd"')
            ):
                hash_exposed = True
                self._add(Finding(
                    title="Hash de mot de passe retourné dans la réponse API",
                    severity="high",
                    category="Sensitive Data Exposure",
                    description=f"Le hash du mot de passe est inclus dans la réponse de {path}.",
                    evidence=f"Champ sensible détecté dans : {path}",
                    remediation="Exclure systématiquement les champs sensibles des sérialiseurs de réponse.",
                    cvss_score=7.5,
                ))
        if found:
            self._add(Finding(
                title="Données sensibles dans les réponses API",
                severity="high",
                category="Sensitive Data Exposure",
                description=f"Patterns sensibles trouvés : {found[:5]}",
                evidence=f"Endpoints : {list({p for p, _ in found[:3]})}",
                remediation="Appliquer le principe de minimisation. Ne jamais retourner secrets, PII ou clés dans les réponses.",
                cvss_score=7.5,
            ))

    # ── Check 8: Mass Assignment ───────────────────────────────────────────────

    def _check_mass_assignment(self):
        probe_paths = [
            "/api/profile", "/api/user", "/api/me",
            "/api/account", "/api/v1/me", "/api/users/me",
        ]
        for path in probe_paths:
            r_get = self._get(path)
            if not r_get or r_get.status_code != 200:
                continue
            try:
                original = r_get.json()
            except Exception:
                continue
            base = dict(original) if isinstance(original, dict) else {}
            base.update(_MASS_ASSIGN)
            for method in ("put", "patch"):
                try:
                    fn = getattr(self.client, method)
                    url = path if "://" in path else self.target + path
                    r2 = fn(url, json=base)
                    if r2.status_code in (200, 201, 204):
                        try:
                            updated = r2.json()
                            if isinstance(updated, dict):
                                for k, v in _MASS_ASSIGN.items():
                                    if updated.get(k) == v:
                                        self._add(Finding(
                                            title="Mass Assignment — élévation de privilèges",
                                            severity="critical",
                                            category="Broken Access Control",
                                            description=f"Le champ '{k}={v}' a été accepté et appliqué via {method.upper()} {path}.",
                                            evidence=f"Payload : {list(_MASS_ASSIGN.keys())} → {k}={updated.get(k)}",
                                            remediation="Utiliser une allowlist stricte des champs acceptés. Ne jamais binder directement le corps de la requête.",
                                            cvss_score=9.1,
                                        ))
                                        return
                        except Exception:
                            pass
                except Exception:
                    pass

    # ── Check 9: Rate Limiting ────────────────────────────────────────────────

    def _check_rate_limiting(self):
        login_url = self._find_login_url()
        if not login_url:
            return
        fmt = self._login_format(login_url)
        if not fmt:
            self._inconclusive(
                "Limitation de débit sur la connexion — test non réalisé", login_url,
                "l'endpoint n'a reconnu aucun des formats de requête essayés (JSON, formulaire encodé)",
            )
            return

        # Phase 1 — brute-force sur UN compte (compte fictif : on ne verrouille jamais
        # le vrai compte de l'utilisateur).
        attempts, statuses, understood = 15, [], 0
        for _ in range(attempts):
            r = self._login_attempt(login_url, fmt, "suturasec_bruteforce_probe", "wrong_password_x")
            statuses.append(r.status_code if r is not None else None)
            understood += self._is_login_rejection(r)
            if r is not None and r.status_code == 429:
                break
        if 429 not in statuses:
            if understood == 0:
                self._inconclusive(
                    "Limitation de débit sur la connexion — test non réalisé", login_url,
                    f"les tentatives n'ont pas été traitées comme des échecs de connexion (statuts : {statuses[:5]}…)",
                )
                return
            self._add(Finding(
                title="Absence de limitation de débit sur le endpoint de connexion",
                severity="high",
                category="Broken Authentication",
                description=(
                    f"{attempts} tentatives invalides consécutives sur le même compte n'ont pas "
                    f"déclenché de blocage (HTTP 429) sur {login_url}. Un attaquant peut tester "
                    "des mots de passe sans limite (brute-force)."
                ),
                evidence=f"{attempts} POST ({fmt['encoding']}) vers {login_url} → statuts : {statuses}",
                remediation="Bloquer après 5 échecs / 15 min par compte ET par IP. CAPTCHA après N échecs. Redis + SlowAPI en production.",
                cvss_score=7.5,
            ))
            return

        # Phase 2 — password spraying : un échec sur chacun de plusieurs comptes différents.
        # Une limite uniquement par compte ne bloque pas ce scénario.
        # 25 comptes : au-dessus des seuils globaux usuels (10–20 échecs / IP).
        spray, spray_statuses = 25, []
        for i in range(spray):
            r = self._login_attempt(login_url, fmt, f"suturasec_spray_probe_{i}", "wrong_password_x")
            spray_statuses.append(r.status_code if r is not None else None)
            if r is not None and r.status_code == 429:
                break
        if 429 not in spray_statuses:
            self._add(Finding(
                title="Limitation de débit par compte uniquement — password spraying possible",
                severity="medium",
                category="Broken Authentication",
                description=(
                    f"Le brute-force sur un compte est bien bloqué (HTTP 429 après {len(statuses)} "
                    f"tentatives), mais {spray} tentatives sur {spray} comptes différents depuis la "
                    "même IP n'ont déclenché aucun blocage. Un attaquant peut essayer un mot de "
                    "passe courant sur de nombreux comptes (password spraying, credential stuffing)."
                ),
                evidence=(
                    f"Même compte : {statuses} · Comptes différents : {spray_statuses} "
                    f"({fmt['encoding']}, {login_url})"
                ),
                remediation="Ajouter une limite globale par IP (ex. 20 échecs / 15 min, tous comptes confondus) en plus de la limite par compte.",
                cvss_score=5.3,
            ))

    # ── Check 10: Authentication Bypass ──────────────────────────────────────

    @staticmethod
    def _is_auth_success(r) -> bool:
        """
        Critères stricts pour éviter les faux positifs sur les pages HTML
        contenant des mots comme 'token' (CSRF token dans les formulaires).

        Un vrai bypass doit :
          1. Retourner JSON (Content-Type application/json)
          2. Contenir un JWT (commence par eyJ) OU un champ access_token/session_token
        """
        if r is None or r.status_code not in (200, 201):
            return False
        ct = r.headers.get("content-type", "")
        if "application/json" not in ct:
            return False
        try:
            data = r.json()
        except Exception:
            return False
        # Cherche un token JWT ou un champ session/access
        for key in ("access_token", "token", "session_token", "id_token", "jwt"):
            val = data.get(key, "")
            if isinstance(val, str) and val.startswith("eyJ"):
                return True
        return False

    def _check_auth_bypass(self):
        login_url = self._find_login_url()
        if not login_url:
            return

        title_na = "Injection SQL sur la connexion — test non réalisé"
        fmt = self._login_format(login_url)
        if not fmt:
            self._inconclusive(
                title_na, login_url,
                "l'endpoint n'a reconnu aucun des formats de requête essayés (JSON, formulaire encodé)",
            )
            return

        # Baseline : des identifiants clairement faux doivent être refusés « proprement »
        baseline = self._login_attempt(login_url, fmt, "__baseline_user__", "__baseline_pass__")
        if self._is_auth_success(baseline):
            self._inconclusive(title_na, login_url, "l'endpoint renvoie un token même pour des identifiants invalides")
            return
        if baseline is not None and baseline.status_code == 429:
            self._inconclusive(title_na, login_url, "l'endpoint bloque déjà les tentatives (HTTP 429)")
            return

        successes, tested, not_processed = [], 0, []
        for user_payload, pwd_payload in _SQLI_PAYLOADS:
            r = self._login_attempt(login_url, fmt, user_payload, pwd_payload)
            if self._is_auth_success(r):
                successes.append(user_payload)
                break
            if self._is_login_rejection(r):
                tested += 1
            else:
                # 422 « format d'email invalide », 429, erreur… : le payload n'a pas
                # atteint la requête SQL, on ne peut rien conclure pour lui.
                not_processed.append((user_payload, r.status_code if r is not None else None))

        if successes:
            self._add(Finding(
                title="Injection SQL sur le formulaire de connexion — bypass authentification",
                severity="critical",
                category="Injection",
                description=f"Des payloads SQLi ont contourné l'authentification : {successes[:3]}",
                evidence=f"Payloads ({fmt['encoding']}, champ « {fmt['id']} ») : {successes[:3]} → HTTP 200 + token",
                remediation="Utiliser des requêtes paramétrées. Ne jamais concaténer les entrées dans les requêtes SQL.",
                cvss_score=9.8,
            ))
        elif tested == 0:
            self._inconclusive(
                title_na, login_url,
                f"aucun payload n'a été traité comme une tentative de connexion (réponses : {not_processed})",
            )
        else:
            partial = (
                f" {len(not_processed)} payload(s) rejeté(s) avant traitement : {not_processed}."
                if not_processed else ""
            )
            self._add(Finding(
                title="Résistance aux injections SQL basiques — vérifiée",
                severity="info",
                category="Injection",
                description=(
                    f"{tested} payload(s) SQLi classique(s) sur {len(_SQLI_PAYLOADS)} ont été traités par "
                    f"l'endpoint de connexion et correctement refusés.{partial}"
                ),
                evidence=f"Endpoint : {login_url} · format {fmt['encoding']}, champ « {fmt['id']} »",
                remediation="Continuer à utiliser des requêtes préparées. Effectuer un pentest approfondi avec un outil dédié.",
                cvss_score=0.0,
            ))
