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
            self._check_rate_limiting,
            self._check_auth_bypass,
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
        accessible = []
        for path in _ADMIN_PATHS:
            r = self._get(path)
            if r and r.status_code in (200, 201) and len(r.text) > 100:
                if "login" not in str(r.url).lower():
                    accessible.append(path)
            if len(accessible) >= 3:
                break

        if accessible:
            self._add(Finding(
                title="Routes d'administration accessibles avec un compte standard",
                severity="critical",
                category="Broken Access Control",
                description=f"Des endpoints admin/gestion retournent HTTP 200 pour un compte utilisateur normal : {accessible}",
                evidence=f"Paths accessibles : {accessible}",
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
                    if r.status_code in (200, 201):
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
        idor_found = []
        for path_tmpl in _IDOR_PATHS[:10]:
            for test_id in (1, 2, 99999):
                r = self._get(path_tmpl.replace("{id}", str(test_id)))
                if r and r.status_code == 200 and len(r.text) > 50:
                    try:
                        text = json.dumps(r.json()).lower()
                        if any(k in text for k in ("email", "username", "name", "phone", "address")):
                            idor_found.append(path_tmpl.replace("{id}", str(test_id)))
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
                evidence=f"Exemples accessibles (HTTP 200 + PII) : {idor_found[:3]}",
                remediation="Vérifier à chaque requête que l'utilisateur est propriétaire de la ressource. Utiliser des UUIDs non séquentiels.",
                cvss_score=8.0,
            ))

    # ── Check 6: CSRF ─────────────────────────────────────────────────────────

    def _check_csrf(self):
        evil = "https://evil.example.com"
        csrf_paths = []
        for path in ["/api/profile", "/api/user", "/api/settings", "/api/v1/user", "/api/account", "/api/me"]:
            r = self._post(
                path,
                json={"test": "csrf_probe"},
                headers={"Origin": evil, "Referer": f"{evil}/attack"},
            )
            if r and r.status_code in (200, 201, 204):
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
        blocked = 0
        for i in range(15):
            r = self._post(
                login_url,
                json={"username": f"ratelimit_probe_{i}", "password": "wrong_password_x"},
            )
            if r and r.status_code == 429:
                blocked += 1
        if blocked == 0:
            self._add(Finding(
                title="Absence de limitation de débit sur le endpoint de connexion",
                severity="high",
                category="Broken Authentication",
                description=f"15 tentatives invalides consécutives n'ont pas déclenché HTTP 429 sur {login_url}. Vulnérable au brute-force.",
                evidence=f"15 requêtes vers {login_url} sans 429",
                remediation="Implémenter rate-limiting : 5 tentatives/15 min par IP+login. CAPTCHA après N échecs. Utiliser Redis + SlowAPI en production.",
                cvss_score=7.5,
            ))

    # ── Check 10: Authentication Bypass ──────────────────────────────────────

    def _check_auth_bypass(self):
        login_url = self._find_login_url()
        if not login_url:
            return
        successes = []
        for user_payload, pwd_payload in _SQLI_PAYLOADS:
            for id_key in ("username", "email"):
                try:
                    r = self.client.post(
                        login_url,
                        json={id_key: user_payload, "password": pwd_payload},
                        headers={"Content-Type": "application/json"},
                    )
                    if r and r.status_code in (200, 201):
                        text = r.text.lower()
                        if any(k in text for k in ("token", "access_token", "dashboard", "logged")):
                            successes.append(user_payload)
                            break
                except Exception:
                    pass
            if successes:
                break

        if successes:
            self._add(Finding(
                title="Injection SQL sur le formulaire de connexion — bypass authentification",
                severity="critical",
                category="Injection",
                description=f"Des payloads SQLi ont contourné l'authentification : {successes[:3]}",
                evidence=f"Payloads : {successes[:3]} → HTTP 200 + token",
                remediation="Utiliser des requêtes paramétrées. Ne jamais concaténer les entrées dans les requêtes SQL.",
                cvss_score=9.8,
            ))
        else:
            self._add(Finding(
                title="Résistance aux injections SQL basiques — vérifiée",
                severity="info",
                category="Injection",
                description="5 payloads SQLi classiques testés sur le formulaire de connexion sans succès.",
                evidence=f"Endpoint testé : {login_url}",
                remediation="Continuer à utiliser des requêtes préparées. Effectuer un pentest approfondi avec un outil dédié.",
                cvss_score=0.0,
            ))
