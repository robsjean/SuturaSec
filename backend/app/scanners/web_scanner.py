"""
Phase 2 — Web Scanner
Checks : HTTP Security Headers, SSL/TLS, Information Disclosure,
         Cookie Security, CORS, Sensitive Files, HTTP Methods,
         SQL Injection, XSS Reflection, Technology Fingerprinting,
         Open Redirect, Rate Limiting.
"""

import re
import ssl
import socket
import datetime
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urlencode, urljoin, parse_qs, urlunparse

import httpx


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str          # critical | high | medium | low | info
    category: str
    description: str
    evidence: str
    remediation: str
    cvss_score: Optional[float] = None


# CVSS indicatifs par sévérité (utilisés quand le check n'en précise pas)
_DEFAULT_CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.1, "info": 0.0}

# User-Agent imitant un navigateur réel pour éviter les blocages anti-bot
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
}

# Patterns d'erreurs SQL par technologie
_SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that (corresponds to|pertains to) your MySQL server version",
    r"ORA-[0-9]{4,5}",           # Oracle
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark",   # MSSQL
    r"quoted string not properly terminated",  # Oracle
    r"pg_query\(\).*:.*ERROR",   # PostgreSQL
    r"ERROR:\s+syntax error at or near",
    r"PSQLException",
    r"SQLiteException",
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",
    r"com\.microsoft\.sqlserver",
    r"Syntax error or access violation",
    r"SQLSTATE\[",
]


# ---------------------------------------------------------------------------
# Scanner principal
# ---------------------------------------------------------------------------

class WebScanner:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target.strip()
        if not self.target.startswith(("http://", "https://")):
            self.target = "https://" + self.target
        self.parsed = urlparse(self.target)
        self.timeout = timeout
        self.findings: List[Finding] = []
        self._response: Optional[httpx.Response] = None

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        try:
            self._response = httpx.get(
                self.target,
                headers=_HEADERS,
                follow_redirects=True,
                timeout=self.timeout,
                verify=False,  # on vérifie SSL séparément pour garder le contrôle
            )
        except httpx.ConnectError:
            self.findings.append(Finding(
                title="Cible inaccessible",
                severity="info",
                category="Connectivity",
                description="Impossible de se connecter à la cible.",
                evidence=self.target,
                remediation="Vérifiez que l'URL est correcte et que la cible est en ligne.",
            ))
            return self.findings
        except Exception as e:
            self.findings.append(Finding(
                title="Erreur de connexion",
                severity="info",
                category="Connectivity",
                description=str(e),
                evidence=self.target,
                remediation="Vérifiez l'URL cible.",
            ))
            return self.findings

        self._check_https_enforcement()
        self._check_ssl_certificate()
        self._check_security_headers()
        self._check_information_disclosure()
        self._check_cookie_security()
        self._check_cors()
        self._check_sensitive_files()
        self._check_http_methods()
        self._check_technology_fingerprinting()
        self._check_sql_injection()
        self._check_xss_reflection()
        self._check_open_redirect()
        self._check_rate_limiting()

        return self.findings

    # ------------------------------------------------------------------
    # 1. HTTPS enforcement
    # ------------------------------------------------------------------

    def _check_https_enforcement(self):
        if self.parsed.scheme == "http":
            try:
                r = httpx.get(
                    self.target.replace("http://", "https://", 1),
                    headers=_HEADERS,
                    follow_redirects=False,
                    timeout=self.timeout,
                    verify=False,
                )
                redirects_to_https = (r.status_code in (301, 302, 307, 308))
            except Exception:
                redirects_to_https = False

            if not redirects_to_https:
                self.findings.append(Finding(
                    title="Site accessible en HTTP sans redirection HTTPS",
                    severity="high",
                    category="A02 – Cryptographic Failures",
                    description="Le site répond en HTTP clair sans forcer une redirection vers HTTPS, exposant les données en transit.",
                    evidence=f"GET {self.target} → HTTP {self._response.status_code} (pas de redirection HTTPS)",
                    remediation="Configurer une redirection 301 de HTTP vers HTTPS et activer HSTS.",
                    cvss_score=7.5,
                ))

    # ------------------------------------------------------------------
    # 2. SSL / TLS
    # ------------------------------------------------------------------

    def _check_ssl_certificate(self):
        if self.parsed.scheme != "https":
            return

        hostname = self.parsed.hostname
        port = self.parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=self.timeout), server_hostname=hostname) as conn:
                cert = conn.getpeercert()
                protocol = conn.version()

            # Expiration
            not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.datetime.utcnow()).days

            if days_left < 0:
                self.findings.append(Finding(
                    title="Certificat SSL expiré",
                    severity="critical",
                    category="A02 – Cryptographic Failures",
                    description="Le certificat TLS est expiré. Les navigateurs afficheront une erreur de sécurité.",
                    evidence=f"Expiré le {not_after.strftime('%Y-%m-%d')} ({abs(days_left)} jours).",
                    remediation="Renouveler le certificat immédiatement (Let's Encrypt ou CA commerciale).",
                    cvss_score=9.1,
                ))
            elif days_left < 30:
                self.findings.append(Finding(
                    title="Certificat SSL expire bientôt",
                    severity="high",
                    category="A02 – Cryptographic Failures",
                    description=f"Le certificat expire dans {days_left} jours.",
                    evidence=f"Expiration : {not_after.strftime('%Y-%m-%d')}",
                    remediation="Planifier le renouvellement du certificat avant expiration.",
                    cvss_score=7.0,
                ))

            # Protocole faible
            if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                self.findings.append(Finding(
                    title=f"Protocole TLS faible : {protocol}",
                    severity="high",
                    category="A02 – Cryptographic Failures",
                    description=f"Le serveur négocie {protocol}, un protocole obsolète avec des vulnérabilités connues (POODLE, BEAST).",
                    evidence=f"Protocole négocié : {protocol}",
                    remediation="Désactiver TLS 1.0 et 1.1. Activer uniquement TLS 1.2 et TLS 1.3.",
                    cvss_score=7.4,
                ))

        except ssl.SSLCertVerificationError as e:
            self.findings.append(Finding(
                title="Certificat SSL invalide ou auto-signé",
                severity="high",
                category="A02 – Cryptographic Failures",
                description="Le certificat ne peut pas être validé par une autorité de certification reconnue.",
                evidence=str(e),
                remediation="Utiliser un certificat signé par une CA reconnue (ex : Let's Encrypt).",
                cvss_score=7.5,
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 3. En-têtes de sécurité HTTP
    # ------------------------------------------------------------------

    def _check_security_headers(self):
        if not self._response:
            return
        headers = {k.lower(): v for k, v in self._response.headers.items()}

        checks = [
            (
                "content-security-policy",
                "Content-Security-Policy (CSP) absent",
                "medium",
                "A05 – Security Misconfiguration",
                "L'absence de CSP permet les attaques XSS et l'injection de contenu malveillant.",
                "Définir une politique CSP stricte : Content-Security-Policy: default-src 'self'.",
                5.4,
            ),
            (
                "strict-transport-security",
                "HTTP Strict-Transport-Security (HSTS) absent",
                "high" if self.parsed.scheme == "https" else "medium",
                "A02 – Cryptographic Failures",
                "Sans HSTS, les utilisateurs peuvent être victimes d'attaques de downgrade SSL/TLS.",
                "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                6.5,
            ),
            (
                "x-frame-options",
                "X-Frame-Options absent (Clickjacking)",
                "medium",
                "A05 – Security Misconfiguration",
                "Sans ce header, des attaques de clickjacking peuvent piéger les utilisateurs.",
                "Ajouter : X-Frame-Options: DENY ou utiliser CSP frame-ancestors.",
                5.3,
            ),
            (
                "x-content-type-options",
                "X-Content-Type-Options absent",
                "low",
                "A05 – Security Misconfiguration",
                "Sans ce header, les navigateurs peuvent interpréter les réponses de manière non attendue (MIME sniffing).",
                "Ajouter : X-Content-Type-Options: nosniff",
                3.7,
            ),
            (
                "referrer-policy",
                "Referrer-Policy absent",
                "info",
                "A05 – Security Misconfiguration",
                "Sans politique de référent, des informations sensibles peuvent fuiter via l'en-tête Referer.",
                "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
                None,
            ),
            (
                "permissions-policy",
                "Permissions-Policy absent",
                "info",
                "A05 – Security Misconfiguration",
                "Sans cet en-tête, les fonctionnalités du navigateur (caméra, micro, géolocalisation) ne sont pas restreintes.",
                "Ajouter : Permissions-Policy: geolocation=(), camera=(), microphone=()",
                None,
            ),
        ]

        for header_name, title, severity, category, description, remediation, cvss in checks:
            if header_name not in headers:
                self.findings.append(Finding(
                    title=title,
                    severity=severity,
                    category=category,
                    description=description,
                    evidence=f"Header '{header_name}' absent de la réponse HTTP.",
                    remediation=remediation,
                    cvss_score=cvss,
                ))

    # ------------------------------------------------------------------
    # 4. Information Disclosure
    # ------------------------------------------------------------------

    def _check_information_disclosure(self):
        if not self._response:
            return
        headers = {k.lower(): v for k, v in self._response.headers.items()}

        for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            if hdr in headers:
                val = headers[hdr]
                if re.search(r"[\d.]", val):
                    self.findings.append(Finding(
                        title=f"Version du logiciel exposée ({hdr})",
                        severity="low",
                        category="A05 – Security Misconfiguration",
                        description=f"Le header '{hdr}' révèle la version du serveur, facilitant le ciblage de vulnérabilités connues.",
                        evidence=f"{hdr}: {val}",
                        remediation=f"Masquer ou supprimer le header '{hdr}' dans la configuration serveur.",
                        cvss_score=3.1,
                    ))

    # ------------------------------------------------------------------
    # 5. Sécurité des cookies
    # ------------------------------------------------------------------

    def _check_cookie_security(self):
        if not self._response:
            return

        set_cookie_headers = [
            v for k, v in self._response.headers.multi_items()
            if k.lower() == "set-cookie"
        ]

        for cookie_str in set_cookie_headers:
            cookie_name = cookie_str.split("=")[0].strip()
            parts_lower = cookie_str.lower()

            if "httponly" not in parts_lower:
                self.findings.append(Finding(
                    title=f"Cookie sans attribut HttpOnly : {cookie_name}",
                    severity="medium",
                    category="A05 – Security Misconfiguration",
                    description="Un cookie sans HttpOnly est accessible via JavaScript, exposant la session aux attaques XSS.",
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    remediation="Ajouter l'attribut HttpOnly à tous les cookies de session.",
                    cvss_score=5.4,
                ))

            if self.parsed.scheme == "https" and "; secure" not in parts_lower:
                self.findings.append(Finding(
                    title=f"Cookie sans attribut Secure : {cookie_name}",
                    severity="medium",
                    category="A02 – Cryptographic Failures",
                    description="Un cookie sans l'attribut Secure peut être transmis en clair via HTTP.",
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    remediation="Ajouter l'attribut Secure à tous les cookies sur un site HTTPS.",
                    cvss_score=5.3,
                ))

            if "samesite" not in parts_lower:
                self.findings.append(Finding(
                    title=f"Cookie sans attribut SameSite : {cookie_name}",
                    severity="low",
                    category="A05 – Security Misconfiguration",
                    description="Un cookie sans SameSite peut être envoyé lors d'une requête cross-site (CSRF).",
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    remediation="Ajouter SameSite=Strict ou SameSite=Lax selon les besoins.",
                    cvss_score=3.5,
                ))

    # ------------------------------------------------------------------
    # 6. CORS
    # ------------------------------------------------------------------

    def _check_cors(self):
        if not self._response:
            return
        headers = {k.lower(): v for k, v in self._response.headers.items()}

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            self.findings.append(Finding(
                title="CORS : wildcard + credentials (critique)",
                severity="critical",
                category="A01 – Broken Access Control",
                description="Combiner Access-Control-Allow-Origin: * avec Allow-Credentials: true permet à n'importe quel site d'effectuer des requêtes authentifiées.",
                evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                remediation="Spécifier des origines explicites plutôt que le wildcard '*' avec les credentials.",
                cvss_score=9.1,
            ))
        elif acao == "*":
            self.findings.append(Finding(
                title="CORS : politique trop permissive (wildcard)",
                severity="medium",
                category="A01 – Broken Access Control",
                description="Access-Control-Allow-Origin: * autorise toutes les origines à lire les réponses.",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Restreindre l'en-tête CORS aux origines légitimes connues.",
                cvss_score=5.3,
            ))

    # ------------------------------------------------------------------
    # 7. Fichiers sensibles exposés
    # ------------------------------------------------------------------

    def _check_sensitive_files(self):
        base = f"{self.parsed.scheme}://{self.parsed.netloc}"

        sensitive = [
            # Secrets & configs
            ("/.env",                "critical", "A02 – Cryptographic Failures",    9.8, "Fichier .env exposé — contient potentiellement des secrets, clés API et credentials."),
            ("/.env.local",          "critical", "A02 – Cryptographic Failures",    9.8, "Fichier .env.local exposé."),
            ("/.env.production",     "critical", "A02 – Cryptographic Failures",    9.8, "Fichier .env.production exposé."),
            ("/.git/HEAD",           "high",     "A05 – Security Misconfiguration", 7.5, "Dépôt Git accessible publiquement — code source récupérable."),
            ("/.git/config",         "high",     "A05 – Security Misconfiguration", 7.5, "Configuration Git exposée."),
            ("/config.php",          "critical", "A02 – Cryptographic Failures",    9.1, "Fichier de configuration PHP exposé — credentials DB possibles."),
            ("/configuration.php",   "critical", "A02 – Cryptographic Failures",    9.1, "Fichier de configuration Joomla! exposé."),
            ("/wp-config.php.bak",   "critical", "A02 – Cryptographic Failures",    9.1, "Sauvegarde de la config WordPress exposée."),
            ("/database.yml",        "critical", "A02 – Cryptographic Failures",    9.1, "Fichier database.yml Rails exposé — credentials DB possibles."),
            ("/settings.py",         "high",     "A02 – Cryptographic Failures",    7.5, "Fichier settings.py Django exposé."),
            # Sauvegardes
            ("/backup.zip",          "high",     "A05 – Security Misconfiguration", 7.5, "Archive de sauvegarde accessible publiquement."),
            ("/backup.sql",          "high",     "A05 – Security Misconfiguration", 7.5, "Dump SQL accessible publiquement."),
            ("/dump.sql",            "high",     "A05 – Security Misconfiguration", 7.5, "Dump SQL accessible publiquement."),
            ("/db.sql",              "high",     "A05 – Security Misconfiguration", 7.5, "Dump de base de données accessible."),
            # Debug & info
            ("/phpinfo.php",         "medium",   "A05 – Security Misconfiguration", 5.3, "phpinfo() exposé — révèle la configuration serveur."),
            ("/info.php",            "medium",   "A05 – Security Misconfiguration", 5.3, "phpinfo() exposé."),
            ("/server-status",       "medium",   "A05 – Security Misconfiguration", 5.3, "mod_status Apache accessible — révèle les connexions actives."),
            ("/server-info",         "medium",   "A05 – Security Misconfiguration", 5.3, "mod_info Apache accessible — révèle les modules chargés."),
            # Auth
            ("/.htpasswd",           "critical", "A07 – Identification Failures",   9.1, "Fichier .htpasswd exposé — hashes de mots de passe récupérables."),
            # API & docs
            ("/api/v1",              "info",     "A05 – Security Misconfiguration", None, "Endpoint API v1 accessible — vérifier l'authentification."),
            ("/api/v2",              "info",     "A05 – Security Misconfiguration", None, "Endpoint API v2 accessible."),
            ("/swagger.json",        "medium",   "A05 – Security Misconfiguration", 5.3, "Documentation Swagger/OpenAPI exposée — révèle tous les endpoints."),
            ("/swagger-ui.html",     "medium",   "A05 – Security Misconfiguration", 5.3, "Interface Swagger UI accessible publiquement."),
            ("/openapi.json",        "medium",   "A05 – Security Misconfiguration", 5.3, "Schéma OpenAPI exposé publiquement."),
            ("/api-docs",            "medium",   "A05 – Security Misconfiguration", 5.3, "Documentation API accessible publiquement."),
            # Panels admin CMS
            ("/admin",               "info",     "A05 – Security Misconfiguration", None, "Interface d'administration accessible (vérifier authentification)."),
            ("/wp-admin",            "info",     "A04 – Insecure Design",           None, "Panel admin WordPress détecté."),
            ("/wp-login.php",        "info",     "A04 – Insecure Design",           None, "Page de login WordPress exposée."),
            ("/administrator",       "info",     "A04 – Insecure Design",           None, "Panel admin Joomla! détecté."),
            ("/phpmyadmin",          "high",     "A05 – Security Misconfiguration", 7.5, "phpMyAdmin accessible publiquement — interface de gestion BDD."),
            ("/adminer.php",         "high",     "A05 – Security Misconfiguration", 7.5, "Adminer (gestion BDD) accessible publiquement."),
            # Logs
            ("/logs/error.log",      "high",     "A05 – Security Misconfiguration", 7.5, "Fichier de log accessible — peut contenir des stack traces et données sensibles."),
            ("/error.log",           "high",     "A05 – Security Misconfiguration", 7.5, "Fichier error.log accessible publiquement."),
        ]

        for path, severity, category, cvss, description in sensitive:
            url = base + path
            try:
                r = httpx.get(url, headers=_HEADERS, follow_redirects=False, timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    preview = r.text[:200].strip().replace("\n", " ")
                    self.findings.append(Finding(
                        title=f"Fichier/ressource sensible accessible : {path}",
                        severity=severity,
                        category=category,
                        description=description,
                        evidence=f"GET {url} → 200 OK\nContenu : {preview}",
                        remediation=f"Bloquer l'accès à {path} via la configuration serveur ou .htaccess.",
                        cvss_score=cvss,
                    ))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 8. Méthodes HTTP dangereuses
    # ------------------------------------------------------------------

    def _check_http_methods(self):
        dangerous = ["TRACE", "PUT", "DELETE"]
        for method in dangerous:
            try:
                r = httpx.request(method, self.target, headers=_HEADERS, timeout=self.timeout, verify=False)
                if r.status_code not in (405, 501, 403):
                    self.findings.append(Finding(
                        title=f"Méthode HTTP dangereuse autorisée : {method}",
                        severity="medium" if method == "TRACE" else "high",
                        category="A05 – Security Misconfiguration",
                        description=f"La méthode {method} est acceptée par le serveur, ce qui peut permettre des modifications non autorisées ou des attaques Cross-Site Tracing.",
                        evidence=f"{method} {self.target} → HTTP {r.status_code}",
                        remediation=f"Désactiver la méthode {method} dans la configuration du serveur web.",
                        cvss_score=6.5 if method == "TRACE" else 7.5,
                    ))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 9. Technology Fingerprinting
    # ------------------------------------------------------------------

    def _check_technology_fingerprinting(self):
        if not self._response:
            return

        body = self._response.text.lower()
        headers = {k.lower(): v for k, v in self._response.headers.items()}
        base = f"{self.parsed.scheme}://{self.parsed.netloc}"

        # Detect CMS / Framework
        fingerprints = [
            # WordPress
            (r"wp-content|wp-includes|wordpress", "WordPress détecté", "WordPress est un CMS très ciblé. Maintenez-le à jour et utilisez un WAF.",
             "/wp-json/wp/v2/users"),  # users endpoint often leaks usernames
            # Joomla
            (r'content="joomla|/components/com_', "Joomla! détecté", "Maintenez Joomla! et ses extensions à jour.",
             None),
            # Drupal
            (r'drupal|sites/default/files', "Drupal détecté", "Maintenez Drupal et ses modules à jour.",
             None),
            # Laravel
            (r'laravel_session|laravel|app/Http', "Framework Laravel détecté", "Vérifiez APP_DEBUG=false en production.",
             None),
            # Django
            (r'csrfmiddlewaretoken|django', "Framework Django détecté", "Vérifiez DEBUG=False en production.",
             None),
            # React / Next.js
            (r'__next|_next/static|react', "Application React/Next.js détectée", "Vérifiez que les source maps ne sont pas exposées en production.",
             None),
            # Angular
            (r'ng-version|angular\.min\.js', "Application Angular détectée", "Vérifiez que les source maps ne sont pas exposées.",
             None),
            # Vue.js
            (r'vue\.min\.js|__vue_', "Application Vue.js détectée", "Vérifiez que les source maps ne sont pas exposées.",
             None),
        ]

        detected = []
        for pattern, tech_name, advice, extra_url in fingerprints:
            if re.search(pattern, body):
                detected.append((tech_name, advice, extra_url))

        # Check Server header for technology hints
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")

        for val, label in [(server, "Server"), (x_powered, "X-Powered-By")]:
            if val:
                tech_hints = {
                    "apache": ("Apache HTTP Server", "Maintenez Apache à jour. Désactivez les modules inutiles."),
                    "nginx": ("Nginx", "Maintenez Nginx à jour. Vérifiez la configuration."),
                    "iis": ("Microsoft IIS", "Appliquez les patches Windows/IIS régulièrement."),
                    "php": ("PHP", "Maintenez PHP à jour. Désactivez expose_php."),
                    "asp.net": ("ASP.NET", "Maintenez .NET Framework à jour."),
                    "tomcat": ("Apache Tomcat", "Maintenez Tomcat à jour. Restreignez l'accès à /manager."),
                    "express": ("Node.js/Express", "Cachez le header X-Powered-By. Maintenez les dépendances npm à jour."),
                }
                for key, (name, advice) in tech_hints.items():
                    if key in val.lower():
                        detected.append((f"{name} détecté via {label}", advice, None))

        for tech_name, advice, extra_url in detected:
            evidence = f"Technologie identifiée dans la réponse HTTP de {self.target}"

            # WordPress: check user enumeration endpoint
            wp_enum_evidence = ""
            if extra_url:
                try:
                    r2 = httpx.get(base + extra_url, headers=_HEADERS, timeout=self.timeout, verify=False)
                    if r2.status_code == 200 and "slug" in r2.text:
                        wp_enum_evidence = f"\n⚠️ Enumération utilisateurs possible via {extra_url} → {r2.status_code}"
                        evidence += wp_enum_evidence
                except Exception:
                    pass

            self.findings.append(Finding(
                title=f"Technologie identifiée : {tech_name}",
                severity="info",
                category="A05 – Security Misconfiguration",
                description=f"La technologie utilisée a été identifiée, permettant de cibler des CVE spécifiques. {advice}",
                evidence=evidence,
                remediation=advice,
                cvss_score=None,
            ))

        # WordPress user enumeration (elevated severity)
        if any("WordPress" in t[0] for t in detected):
            try:
                r2 = httpx.get(f"{base}/wp-json/wp/v2/users", headers=_HEADERS, timeout=self.timeout, verify=False)
                if r2.status_code == 200 and "slug" in r2.text:
                    import json as _json
                    users_data = _json.loads(r2.text)
                    usernames = [u.get("slug", "") for u in users_data[:5] if isinstance(u, dict)]
                    self.findings.append(Finding(
                        title="WordPress : énumération des utilisateurs possible",
                        severity="medium",
                        category="A07 – Identification Failures",
                        description="L'API REST WordPress expose les noms d'utilisateurs, facilitant les attaques par dictionnaire.",
                        evidence=f"GET {base}/wp-json/wp/v2/users → 200 OK\nUtilisateurs : {', '.join(usernames)}",
                        remediation="Désactiver l'endpoint /wp-json/wp/v2/users ou restreindre l'accès via un plugin de sécurité (Wordfence, etc.).",
                        cvss_score=5.3,
                    ))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 10. SQL Injection (détection basique — erreurs SQL réfléchies)
    # ------------------------------------------------------------------

    def _check_sql_injection(self):
        """
        Injecte des payloads SQLi dans les paramètres GET existants ou des
        paramètres tests communs. Détecte les erreurs SQL reflétées dans la réponse.
        """
        if not self._response:
            return

        base_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}"
        existing_params = parse_qs(self.parsed.query)

        # Paramètres à tester : ceux déjà dans l'URL + paramètres courants
        test_params = list(existing_params.keys()) or ["id", "page", "q", "search", "cat", "item", "product", "user"]

        sqli_payloads = ["'", "''", "`", "\"", "1' OR '1'='1", "1; SELECT 1--", "' OR 1=1--"]

        already_reported = False

        for param in test_params[:3]:  # Limiter le nombre de requêtes
            for payload in sqli_payloads[:3]:
                if already_reported:
                    break
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    r = httpx.get(test_url, headers=_HEADERS, timeout=self.timeout, verify=False)
                    body = r.text

                    for pattern in _SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            self.findings.append(Finding(
                                title="Injection SQL potentielle détectée",
                                severity="critical",
                                category="A03 – Injection",
                                description=(
                                    "Une erreur SQL a été reflétée dans la réponse HTTP suite à l'injection d'un payload. "
                                    "Cela indique une vulnérabilité d'injection SQL pouvant permettre l'accès ou la destruction de la base de données."
                                ),
                                evidence=f"Payload : {payload!r}\nURL : {test_url}\nErreur SQL détectée (pattern: {pattern})",
                                remediation=(
                                    "Utiliser des requêtes préparées (Prepared Statements) ou un ORM. "
                                    "Ne jamais concaténer directement les entrées utilisateur dans les requêtes SQL."
                                ),
                                cvss_score=9.8,
                            ))
                            already_reported = True
                            break
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # 11. XSS Réfléchi (détection basique)
    # ------------------------------------------------------------------

    def _check_xss_reflection(self):
        """
        Teste la réflexion de payloads XSS dans les paramètres GET.
        Détecte uniquement le XSS réfléchi non encodé (pas DOM-based).
        """
        if not self._response:
            return

        base_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}"
        existing_params = parse_qs(self.parsed.query)
        test_params = list(existing_params.keys()) or ["q", "search", "query", "name", "s", "keyword", "input"]

        xss_marker = "suturasec_xss_probe_7f3a"
        xss_payload = f'"><script>{xss_marker}</script>'

        already_reported = False

        for param in test_params[:3]:
            if already_reported:
                break
            try:
                test_url = f"{base_url}?{param}={xss_payload}"
                r = httpx.get(test_url, headers=_HEADERS, timeout=self.timeout, verify=False)

                # Vérifier si le payload est reflété non encodé
                if xss_marker in r.text and "<script>" in r.text:
                    self.findings.append(Finding(
                        title="XSS Réfléchi potentiel détecté",
                        severity="high",
                        category="A03 – Injection",
                        description=(
                            "Un payload XSS a été réfléchi dans la réponse HTTP sans être encodé. "
                            "Cela indique une vulnérabilité Cross-Site Scripting pouvant permettre "
                            "l'exécution de code JavaScript arbitraire dans le navigateur des victimes."
                        ),
                        evidence=f"Paramètre : {param}\nPayload : {xss_payload}\nURL : {test_url}",
                        remediation=(
                            "Encoder toutes les sorties HTML (htmlspecialchars en PHP, escape en Python/Jinja2). "
                            "Implémenter une politique CSP stricte. Valider et assainir toutes les entrées."
                        ),
                        cvss_score=8.2,
                    ))
                    already_reported = True
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 12. Open Redirect
    # ------------------------------------------------------------------

    def _check_open_redirect(self):
        """
        Teste les paramètres de redirection courants pour détecter les open redirects.
        """
        base_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}"
        redirect_params = ["redirect", "url", "next", "return", "returnTo", "continue",
                           "goto", "dest", "destination", "redir", "redirect_uri", "callback"]
        evil_url = "https://evil.example.com/phishing"

        for param in redirect_params:
            try:
                test_url = f"{base_url}?{param}={evil_url}"
                r = httpx.get(test_url, headers=_HEADERS, follow_redirects=False,
                              timeout=self.timeout, verify=False)

                # Redirection vers notre URL malveillante ?
                location = r.headers.get("location", "")
                if r.status_code in (301, 302, 307, 308) and "evil.example.com" in location:
                    self.findings.append(Finding(
                        title="Open Redirect détecté",
                        severity="medium",
                        category="A01 – Broken Access Control",
                        description=(
                            f"Le paramètre '{param}' permet de rediriger vers une URL arbitraire. "
                            "Cela peut être exploité pour des campagnes de phishing en utilisant le domaine légitime comme intermédiaire."
                        ),
                        evidence=f"GET {test_url}\n→ HTTP {r.status_code} Location: {location}",
                        remediation=(
                            "Valider les URLs de redirection via une liste blanche. "
                            "Ne jamais rediriger vers une URL fournie directement par l'utilisateur sans validation."
                        ),
                        cvss_score=6.1,
                    ))
                    break  # Un seul finding suffisant
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 13. Rate Limiting
    # ------------------------------------------------------------------

    def _check_rate_limiting(self):
        """
        Envoie 10 requêtes rapides et vérifie si le serveur applique un rate limiting.
        """
        import time

        responses = []
        try:
            for _ in range(10):
                r = httpx.get(self.target, headers=_HEADERS, timeout=self.timeout, verify=False)
                responses.append(r.status_code)
        except Exception:
            return

        # Si aucun 429/503 n'a été reçu, le rate limiting est absent
        rate_limited = any(code in (429, 503) for code in responses)
        has_header_protection = self._response and (
            "x-ratelimit-limit" in {k.lower() for k in self._response.headers}
            or "retry-after" in {k.lower() for k in self._response.headers}
        )

        if not rate_limited and not has_header_protection:
            self.findings.append(Finding(
                title="Absence de rate limiting détectée",
                severity="medium",
                category="A05 – Security Misconfiguration",
                description=(
                    "Le serveur n'applique pas de rate limiting visible (aucun HTTP 429 reçu après 10 requêtes rapides, "
                    "aucun header X-RateLimit-Limit). Cela expose le site aux attaques par force brute et DoS applicatif."
                ),
                evidence=f"10 requêtes envoyées → statuts : {responses}. Aucun 429 reçu.",
                remediation=(
                    "Implémenter un rate limiting (ex : nginx limit_req, fail2ban, Cloudflare, "
                    "ou middleware Express/FastAPI rate-limiter). Retourner HTTP 429 avec Retry-After."
                ),
                cvss_score=5.3,
            ))


# ---------------------------------------------------------------------------
# Calcul du risk score et du summary
# ---------------------------------------------------------------------------

def compute_risk_score(findings: List[Finding]) -> float:
    """Score 0–10 basé sur le CVSS moyen pondéré par sévérité."""
    if not findings:
        return 0.0

    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    total_weight = 0
    weighted_sum = 0.0

    for f in findings:
        w = weights.get(f.severity, 0)
        score = f.cvss_score if f.cvss_score is not None else _DEFAULT_CVSS.get(f.severity, 0.0)
        weighted_sum += score * w
        total_weight += w

    if total_weight == 0:
        return 0.0

    raw = weighted_sum / total_weight
    return round(min(raw, 10.0), 1)


def generate_summary(findings: List[Finding], target: str) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = sum(counts.values())
    if total == 0:
        return f"Aucune vulnérabilité détectée sur {target}."

    parts = []
    if counts["critical"]: parts.append(f"{counts['critical']} critique(s)")
    if counts["high"]:     parts.append(f"{counts['high']} élevée(s)")
    if counts["medium"]:   parts.append(f"{counts['medium']} moyenne(s)")
    if counts["low"]:      parts.append(f"{counts['low']} faible(s)")
    if counts["info"]:     parts.append(f"{counts['info']} info")

    return f"Analyse de {target} terminée. {total} résultat(s) : {', '.join(parts)}."
