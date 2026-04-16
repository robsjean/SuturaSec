"""
Compliance Engine — SuturaSec
Évalue la conformité d'un scan vis-à-vis de 4 référentiels :
  - OWASP Top 10 2021      (10 contrôles)
  - PCI-DSS v4.0            (9 contrôles)
  - ISO 27001:2022 Annex A  (8 contrôles)
  - GDPR Article 32         (6 contrôles)

Pour chaque contrôle :
  - Texte exact du standard
  - Statut : PASS | FAIL | PARTIAL | NA
  - Preuves issues du scan
  - Impact business / légal concret
  - Étapes de remédiation précises
  - Score pondéré par criticité
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from app.scanners.web_scanner import Finding


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ComplianceControl:
    id: str                        # Ex: "OWASP-A01", "PCI-6.4.1"
    framework: str                 # "OWASP Top 10", "PCI-DSS v4.0", …
    category: str                  # Nom du domaine
    title: str                     # Titre court du contrôle
    requirement: str               # Texte exact du standard
    status: str                    # pass | fail | partial | na
    score: int                     # 0–100 pour ce contrôle
    evidence: List[str]            # Preuves tirées des findings
    impact: str                    # Impact business/légal si non conforme
    remediation: List[str]         # Étapes concrètes de remédiation
    weight: float = 1.0            # Poids dans le score global (1–5)
    cwe_references: List[str] = field(default_factory=list)   # CWE associés
    cvss_ceiling: Optional[float] = None  # CVSS max des findings liés


@dataclass
class FrameworkReport:
    framework: str
    version: str
    overall_score: float           # 0–100
    grade: str                     # A+ | A | B | C | D | F
    total_controls: int
    passed: int
    failed: int
    partial: int
    na: int
    controls: List[ComplianceControl]
    critical_gaps: List[str]       # Lacunes les plus critiques
    compliance_statement: str      # Résumé exécutif


def _grade(score: float) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


# ---------------------------------------------------------------------------
# Helpers de matching sur les findings
# ---------------------------------------------------------------------------

def _has_category(findings: List[Finding], *keywords: str) -> List[Finding]:
    """Retourne les findings dont la catégorie contient l'un des mots-clés."""
    result = []
    for f in findings:
        cat = (f.category or "").lower()
        if any(k.lower() in cat for k in keywords):
            result.append(f)
    return result


def _has_title(findings: List[Finding], *keywords: str) -> List[Finding]:
    """Retourne les findings dont le titre contient l'un des mots-clés."""
    result = []
    for f in findings:
        title = (f.title or "").lower()
        if any(k.lower() in title for k in keywords):
            result.append(f)
    return result


def _has_severity(findings: List[Finding], *severities: str) -> List[Finding]:
    return [f for f in findings if f.severity in severities]


def _evidence_from(findings: List[Finding], max_items: int = 5) -> List[str]:
    """Génère des chaînes d'evidence lisibles depuis une liste de findings."""
    out = []
    for f in findings[:max_items]:
        cvss_str = f" [CVSS {f.cvss_score}]" if f.cvss_score else ""
        out.append(f"[{f.severity.upper()}] {f.title}{cvss_str}")
    return out


def _cvss_max(findings: List[Finding]) -> Optional[float]:
    scores = [f.cvss_score for f in findings if f.cvss_score is not None]
    return max(scores) if scores else None


# ---------------------------------------------------------------------------
# OWASP Top 10 — 2021
# ---------------------------------------------------------------------------

def _evaluate_owasp(findings: List[Finding]) -> FrameworkReport:
    controls: List[ComplianceControl] = []

    # --- A01 : Broken Access Control ---
    ac_findings = _has_category(findings, "A01")
    cors_wild = _has_title(findings, "cors", "wildcard")
    http_methods = _has_title(findings, "méthode http", "PUT", "DELETE", "TRACE")
    sensitive_access = _has_title(findings, "sensible", "admin", "phpmyadmin", "adminer")
    a01_hits = ac_findings + cors_wild + http_methods + sensitive_access
    a01_hits = list({id(f): f for f in a01_hits}.values())

    if _has_title(a01_hits, "critique") or any(f.severity == "critical" for f in a01_hits):
        a01_status, a01_score = "fail", 0
    elif a01_hits:
        a01_status, a01_score = "partial", 40
    else:
        a01_status, a01_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A01",
        framework="OWASP Top 10",
        category="Contrôle d'accès",
        title="A01:2021 — Broken Access Control",
        requirement=(
            "Les restrictions sur ce que les utilisateurs authentifiés sont autorisés à faire "
            "ne sont souvent pas correctement appliquées. Les attaquants peuvent exploiter ces failles "
            "pour accéder à des fonctionnalités ou des données non autorisées. "
            "(OWASP Top 10:2021 — Catégorie la plus répandue, 94% des applications testées présentent "
            "une forme de contrôle d'accès défaillant.)"
        ),
        status=a01_status,
        score=a01_score,
        evidence=_evidence_from(a01_hits) or ["Aucune violation de contrôle d'accès détectée."],
        impact=(
            "Une défaillance du contrôle d'accès peut permettre à un attaquant d'accéder à des données "
            "confidentielles, de modifier ou supprimer des enregistrements, d'élever ses privilèges ou "
            "de prendre le contrôle total de l'application. Impact juridique : violation possible du RGPD "
            "avec amendes jusqu'à 4% du CA mondial."
        ),
        remediation=[
            "Implémenter un mécanisme de contrôle d'accès côté serveur — refuser par défaut.",
            "Désactiver les méthodes HTTP non nécessaires (PUT, DELETE, TRACE) via la configuration serveur.",
            "Restreindre les politiques CORS aux origines explicitement autorisées.",
            "Protéger les interfaces d'administration par authentification forte + restriction IP.",
            "Journaliser et alerter sur les échecs de contrôle d'accès (SIEM).",
            "Effectuer des tests d'intrusion réguliers axés sur le contrôle d'accès horizontal/vertical.",
        ],
        weight=5.0,
        cwe_references=["CWE-284", "CWE-285", "CWE-639"],
        cvss_ceiling=_cvss_max(a01_hits),
    ))

    # --- A02 : Cryptographic Failures ---
    crypto_findings = _has_category(findings, "A02")
    no_https = _has_title(findings, "http sans redirection", "http clair")
    weak_tls = _has_title(findings, "tls faible", "tlsv1", "SSLv", "ssl expiré", "ssl invalide")
    no_hsts = _has_title(findings, "hsts")
    cookie_secure = _has_title(findings, "cookie sans attribut secure")
    a02_critical = no_https + weak_tls + _has_title(findings, "ssl expiré")
    a02_all = crypto_findings

    if a02_critical:
        a02_status, a02_score = "fail", 0
    elif a02_all:
        a02_status, a02_score = "partial", 35
    elif no_hsts or cookie_secure:
        a02_status, a02_score = "partial", 60
    else:
        a02_status, a02_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A02",
        framework="OWASP Top 10",
        category="Cryptographie",
        title="A02:2021 — Cryptographic Failures",
        requirement=(
            "Les échecs liés à la cryptographie (anciennement 'Sensitive Data Exposure') exposent "
            "des données sensibles en transit ou au repos. Cela inclut l'absence de chiffrement, "
            "l'utilisation d'algorithmes faibles ou obsolètes (MD5, SHA1, RC4, DES, TLS 1.0/1.1) "
            "et une mauvaise gestion des certificats. (OWASP Top 10:2021 — 2e position)"
        ),
        status=a02_status,
        score=a02_score,
        evidence=_evidence_from(a02_all) or ["Chiffrement correctement configuré."],
        impact=(
            "L'absence de chiffrement expose les données en transit aux attaques Man-in-the-Middle (MitM). "
            "Un certificat expiré ou invalide déclenche des alertes de sécurité navigateur qui détruisent "
            "la confiance utilisateur. TLS 1.0/1.1 sont vulnérables à POODLE (CVE-2014-3566) et BEAST. "
            "Non-conformité PCI-DSS Req.4.2.1 : amende potentielle + révocation de l'acceptation de paiement."
        ),
        remediation=[
            "Forcer HTTPS via redirection 301 permanente sur tout le trafic HTTP.",
            "Activer HSTS avec max-age minimum 31536000 (1 an) + includeSubDomains.",
            "Désactiver TLS 1.0 et TLS 1.1 — activer TLS 1.2 minimum, TLS 1.3 recommandé.",
            "Renouveler les certificats avant expiration — utiliser Let's Encrypt avec renouvellement automatique.",
            "Ajouter l'attribut Secure à tous les cookies contenant des données de session.",
            "Vérifier la configuration avec SSL Labs (ssllabs.com/ssltest) — viser grade A+.",
        ],
        weight=5.0,
        cwe_references=["CWE-261", "CWE-311", "CWE-327", "CWE-328"],
        cvss_ceiling=_cvss_max(a02_all),
    ))

    # --- A03 : Injection ---
    sqli = _has_title(findings, "injection sql", "sql")
    xss = _has_title(findings, "xss", "cross-site scripting")
    inj_all = sqli + xss

    if sqli:
        a03_status, a03_score = "fail", 0
    elif xss:
        a03_status, a03_score = "fail", 0
    elif _has_category(findings, "A03"):
        a03_status, a03_score = "partial", 30
    else:
        a03_status, a03_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A03",
        framework="OWASP Top 10",
        category="Injection",
        title="A03:2021 — Injection",
        requirement=(
            "Une application est vulnérable aux injections lorsque des données fournies par l'utilisateur "
            "ne sont pas validées, filtrées ou assainies. Cela inclut SQL, NoSQL, OS, LDAP, XSS. "
            "Les injections peuvent entraîner la perte de données, le contournement d'authentification "
            "et la compromission complète du serveur. (OWASP Top 10:2021 — 3e position, CWE-79 reste "
            "la vulnérabilité la plus répandue dans les CVE répertoriées)"
        ),
        status=a03_status,
        score=a03_score,
        evidence=_evidence_from(inj_all) or ["Aucune injection détectée lors du scan passif."],
        impact=(
            "Une injection SQL (CWE-89) permet à un attaquant d'extraire, modifier ou supprimer "
            "l'intégralité de la base de données — CVSS 9.8 (Critique). "
            "Un XSS réfléchi (CWE-79) permet le vol de cookies de session, le phishing ciblé et la "
            "propagation de malwares via le domaine de confiance. "
            "RGPD Art.32 : obligation de protéger les données contre les attaques par injection."
        ),
        remediation=[
            "PRIORITÉ 1 : Utiliser exclusivement des requêtes préparées (Prepared Statements) avec des "
            "paramètres liés — ne jamais concaténer des entrées utilisateur dans des requêtes SQL.",
            "Utiliser un ORM (SQLAlchemy, Hibernate, Sequelize) qui gère l'échappement automatiquement.",
            "Encoder toutes les sorties vers le navigateur (htmlspecialchars, Jinja2 autoescaping, React JSX).",
            "Implémenter une Content-Security-Policy (CSP) stricte pour bloquer l'exécution de scripts non autorisés.",
            "Déployer un Web Application Firewall (WAF) avec règles OWASP Core Rule Set (CRS).",
            "Effectuer une revue de code ciblée sur tous les points d'entrée utilisateur.",
        ],
        weight=5.0,
        cwe_references=["CWE-79", "CWE-89", "CWE-77"],
        cvss_ceiling=_cvss_max(inj_all),
    ))

    # --- A04 : Insecure Design ---
    rate_limit = _has_title(findings, "rate limiting")
    open_redir = _has_title(findings, "open redirect")
    dev_server = _has_title(findings, "développement", "dev server", "jupyter", "docker")
    a04_all = rate_limit + open_redir + dev_server

    if any(f.severity in ("critical", "high") for f in a04_all):
        a04_status, a04_score = "fail", 20
    elif a04_all:
        a04_status, a04_score = "partial", 55
    else:
        a04_status, a04_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A04",
        framework="OWASP Top 10",
        category="Conception",
        title="A04:2021 — Insecure Design",
        requirement=(
            "La conception non sécurisée est une catégorie large représentant différentes failles liées "
            "à des lacunes de conception, absentes de la conception initiale. La protection des données "
            "sensibles doit être intégrée dès la phase de conception (Security by Design). "
            "Cela inclut l'absence de contrôles de sécurité métier, de limitation de taux et de validation."
        ),
        status=a04_status,
        score=a04_score,
        evidence=_evidence_from(a04_all) or ["Aucune lacune de conception majeure détectée."],
        impact=(
            "L'absence de rate limiting expose l'application aux attaques de credential stuffing, de brute-force "
            "sur les mots de passe et aux attaques DoS applicatives. "
            "Un open redirect permet des campagnes de phishing sophistiquées utilisant votre domaine de confiance. "
            "Les outils de développement exposés (Jupyter, Docker API) peuvent mener à une RCE complète."
        ),
        remediation=[
            "Implémenter un rate limiting sur toutes les routes sensibles (login, API, inscription).",
            "Retourner HTTP 429 (Too Many Requests) avec header Retry-After.",
            "Valider toutes les URLs de redirection via une liste blanche stricte.",
            "Désactiver ou protéger tous les outils de développement avant mise en production.",
            "Conduire des sessions de threat modeling (STRIDE) en phase de conception.",
            "Définir des user stories de sécurité explicites dans les sprints de développement.",
        ],
        weight=3.0,
        cwe_references=["CWE-400", "CWE-601", "CWE-799"],
        cvss_ceiling=_cvss_max(a04_all),
    ))

    # --- A05 : Security Misconfiguration ---
    headers_miss = _has_title(findings, "absent", "manquant", "csp", "x-frame", "hsts",
                               "x-content-type", "referrer-policy", "permissions-policy")
    info_disc = _has_title(findings, "version du logiciel", "phpinfo", "server-status",
                            "server-info", "swagger", "openapi", "api-docs")
    sensitive_files = _has_title(findings, "fichier", "sensible", "accessible")
    a05_all = list({id(f): f for f in headers_miss + info_disc + sensitive_files}.values())

    critical_a05 = [f for f in a05_all if f.severity == "critical"]
    high_a05 = [f for f in a05_all if f.severity == "high"]

    if critical_a05:
        a05_status, a05_score = "fail", 0
    elif len(high_a05) >= 2:
        a05_status, a05_score = "fail", 15
    elif a05_all:
        a05_status, a05_score = "partial", 45
    else:
        a05_status, a05_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A05",
        framework="OWASP Top 10",
        category="Configuration",
        title="A05:2021 — Security Misconfiguration",
        requirement=(
            "La mauvaise configuration de sécurité est la plus répandue des vulnérabilités. Elle résulte "
            "d'une configuration non sécurisée par défaut, d'une configuration incomplète, d'un stockage "
            "cloud ouvert, d'en-têtes HTTP mal configurés et de messages d'erreur verbeux révélant "
            "des informations sensibles. 90% des applications présentent une mauvaise configuration. "
            "(OWASP Top 10:2021 — 5e position)"
        ),
        status=a05_status,
        score=a05_score,
        evidence=_evidence_from(a05_all) or ["Configuration de sécurité correcte."],
        impact=(
            "Les fichiers de configuration exposés (.env, wp-config.php) contiennent des credentials "
            "en clair permettant une compromission immédiate de la base de données (CVSS 9.8). "
            "L'absence d'en-têtes de sécurité facilite les attaques XSS, clickjacking et MIME sniffing. "
            "Les versions de logiciels exposées permettent un ciblage précis via les CVE publiées."
        ),
        remediation=[
            "Implémenter tous les en-têtes de sécurité HTTP : CSP, HSTS, X-Frame-Options, X-Content-Type-Options.",
            "Bloquer l'accès à tous les fichiers sensibles (.env, .git, config.php, backup.*) via .htaccess ou nginx.",
            "Masquer les versions de logiciels (ServerTokens Prod, expose_php=Off).",
            "Supprimer les pages de debug (phpinfo.php, server-status) en production.",
            "Utiliser des scans automatisés (ce scanner) à chaque déploiement.",
            "Appliquer le principe du moindre privilège sur tous les composants.",
        ],
        weight=4.0,
        cwe_references=["CWE-16", "CWE-2", "CWE-209"],
        cvss_ceiling=_cvss_max(a05_all),
    ))

    # --- A06 : Vulnerable & Outdated Components ---
    cve_findings = _has_title(findings, "cve", "obsolète", "outdated", "vuln", "version")
    old_ssh = _has_title(findings, "sshv1", "openssh", "ssh")
    a06_all = list({id(f): f for f in cve_findings + old_ssh}.values())

    if any(f.severity == "critical" for f in a06_all):
        a06_status, a06_score = "fail", 0
    elif any(f.severity == "high" for f in a06_all):
        a06_status, a06_score = "fail", 20
    elif a06_all:
        a06_status, a06_score = "partial", 55
    else:
        a06_status, a06_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A06",
        framework="OWASP Top 10",
        category="Composants",
        title="A06:2021 — Vulnerable and Outdated Components",
        requirement=(
            "Les composants (bibliothèques, frameworks, modules) tournent avec les mêmes privilèges "
            "que l'application. Si un composant vulnérable est exploité, cela peut entraîner une perte "
            "de données grave ou une compromission du serveur. Les composants incluent OS, serveurs web, "
            "SGBD, APIs, bibliothèques, runtimes. (OWASP Top 10:2021 — 6e position)"
        ),
        status=a06_status,
        score=a06_score,
        evidence=_evidence_from(a06_all) or ["Aucun composant obsolète identifié par le scan."],
        impact=(
            "L'exploitation de composants vulnérables connus (CVE publiées) est triviale — des outils "
            "comme Metasploit fournissent des exploits prêts à l'emploi. Log4Shell (CVE-2021-44228, CVSS 10.0) "
            "et EternalBlue (CVE-2017-0144, CVSS 9.3) illustrent les conséquences catastrophiques. "
            "ISO 27001 Contrôle A.8.8 exige la gestion proactive des vulnérabilités techniques."
        ),
        remediation=[
            "Maintenir un inventaire précis de tous les composants et leurs versions (Software BOM).",
            "Souscrire aux bulletins de sécurité des vendors (CVE feeds, GitHub Security Advisories).",
            "Automatiser la détection des dépendances vulnérables (Dependabot, Snyk, OWASP Dependency-Check).",
            "Appliquer les patches de sécurité dans un délai maximum de 72h pour les vulnérabilités critiques.",
            "Désactiver les composants, fonctionnalités et services non utilisés.",
            "Utiliser uniquement des sources officielles et vérifier l'intégrité des packages (checksums).",
        ],
        weight=4.0,
        cwe_references=["CWE-1104", "CWE-937"],
        cvss_ceiling=_cvss_max(a06_all),
    ))

    # --- A07 : Identification & Authentication Failures ---
    cookie_http = _has_title(findings, "httponly", "samesite")
    ftp_anon = _has_title(findings, "ftp", "anonyme", "anonymous")
    auth_weak = _has_title(findings, "webmin", "phpmyadmin", "adminer", "wordpress : énumération")
    a07_all = list({id(f): f for f in cookie_http + ftp_anon + auth_weak}.values())

    if any(f.severity == "critical" for f in a07_all):
        a07_status, a07_score = "fail", 0
    elif any(f.severity == "high" for f in a07_all):
        a07_status, a07_score = "partial", 30
    elif a07_all:
        a07_status, a07_score = "partial", 60
    else:
        a07_status, a07_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A07",
        framework="OWASP Top 10",
        category="Authentification",
        title="A07:2021 — Identification and Authentication Failures",
        requirement=(
            "La confirmation de l'identité de l'utilisateur, l'authentification et la gestion des sessions "
            "sont essentielles pour se protéger contre les attaques liées à l'authentification. "
            "Les applications peuvent avoir des failles si elles permettent des mots de passe faibles, "
            "manquent de MFA, exposent les sessions dans l'URL ou ont des timeouts insuffisants. "
            "(OWASP Top 10:2021 — 7e position)"
        ),
        status=a07_status,
        score=a07_score,
        evidence=_evidence_from(a07_all) or ["Aucune défaillance d'authentification détectée."],
        impact=(
            "Le FTP anonyme permet à n'importe qui d'accéder aux fichiers du serveur sans authentification. "
            "Les cookies sans HttpOnly peuvent être volés via XSS, permettant le détournement de session. "
            "L'énumération des utilisateurs WordPress facilite les attaques par dictionnaire ciblées. "
            "PCI-DSS Req.8 : exige une identification unique par utilisateur avec authentification forte."
        ),
        remediation=[
            "Désactiver FTP et remplacer par SFTP ou FTPS avec authentification par clé.",
            "Ajouter HttpOnly, Secure et SameSite=Strict à tous les cookies de session.",
            "Implémenter l'authentification multi-facteurs (MFA/2FA) sur tous les accès administratifs.",
            "Désactiver l'endpoint /wp-json/wp/v2/users ou filtrer son accès aux administrateurs.",
            "Configurer des timeouts de session inactifs (15-30 minutes maximum).",
            "Implémenter un verrouillage de compte après 5 tentatives échouées.",
        ],
        weight=4.0,
        cwe_references=["CWE-287", "CWE-306", "CWE-798"],
        cvss_ceiling=_cvss_max(a07_all),
    ))

    # --- A08 : Software & Data Integrity Failures ---
    no_csp = _has_title(findings, "csp", "content-security-policy")
    a08_all = no_csp

    if any(f.severity in ("critical", "high") for f in a08_all):
        a08_status, a08_score = "partial", 40
    elif a08_all:
        a08_status, a08_score = "partial", 65
    else:
        a08_status, a08_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A08",
        framework="OWASP Top 10",
        category="Intégrité",
        title="A08:2021 — Software and Data Integrity Failures",
        requirement=(
            "Les défaillances d'intégrité des logiciels et des données concernent les hypothèses "
            "relatives aux mises à jour, données critiques et pipelines CI/CD sans vérification d'intégrité. "
            "Cela inclut l'absence de Subresource Integrity (SRI), la désérialisation non sécurisée "
            "et les pipelines de mise à jour non sécurisés. (OWASP Top 10:2021 — 8e position)"
        ),
        status=a08_status,
        score=a08_score,
        evidence=_evidence_from(a08_all) or ["Aucune défaillance d'intégrité détectée."],
        impact=(
            "L'absence de CSP permet l'injection de scripts malveillants sans vérification d'intégrité. "
            "Les ressources tierces (CDN) chargées sans Subresource Integrity (SRI) peuvent être "
            "compromises côté fournisseur et servir des scripts malveillants à tous vos utilisateurs "
            "(supply chain attack — cf. incident SolarWinds, Polyfill.io 2024)."
        ),
        remediation=[
            "Implémenter une Content-Security-Policy stricte avec 'script-src' limité aux origines autorisées.",
            "Utiliser Subresource Integrity (SRI) pour toutes les ressources tierces : "
            "<script integrity='sha384-...' crossorigin='anonymous'>",
            "Sécuriser le pipeline CI/CD avec signature des artifacts et vérification des checksums.",
            "Désactiver la désérialisation des données non fiables ou utiliser un format sans état d'exécution (JSON).",
            "Auditer régulièrement les dépendances tierces (npm audit, pip-audit).",
        ],
        weight=3.0,
        cwe_references=["CWE-345", "CWE-353", "CWE-829"],
        cvss_ceiling=None,
    ))

    # --- A09 : Security Logging & Monitoring Failures ---
    log_exposed = _has_title(findings, "log", "error.log")
    no_rate = _has_title(findings, "rate limiting")
    a09_all = log_exposed + no_rate

    if log_exposed:
        a09_status, a09_score = "fail", 10
    elif no_rate:
        a09_status, a09_score = "partial", 50
    else:
        a09_status, a09_score = "pass", 100

    controls.append(ComplianceControl(
        id="OWASP-A09",
        framework="OWASP Top 10",
        category="Journalisation",
        title="A09:2021 — Security Logging & Monitoring Failures",
        requirement=(
            "La journalisation et la surveillance insuffisantes, associées à une intégration défaillante "
            "avec la réponse aux incidents, permettent aux attaquants d'approfondir leurs attaques, "
            "de maintenir la persistance, de pivoter vers d'autres systèmes. "
            "La détection d'une violation prend en moyenne 287 jours. (OWASP Top 10:2021 — 9e position)"
        ),
        status=a09_status,
        score=a09_score,
        evidence=_evidence_from(a09_all) or ["Aucun problème de journalisation détecté publiquement."],
        impact=(
            "Des fichiers de logs accessibles publiquement (error.log) peuvent révéler des stack traces "
            "avec chemins de fichiers, credentials et architecture interne — précieux pour un attaquant. "
            "L'absence de rate limiting empêche la détection des attaques par brute-force. "
            "RGPD Art.33 : obligation de notifier une violation dans les 72h — impossible sans monitoring."
        ),
        remediation=[
            "Bloquer l'accès public à tous les fichiers de log.",
            "Centraliser les logs dans un SIEM (Elastic Stack, Splunk, Graylog) avec alertes temps réel.",
            "Journaliser tous les événements d'authentification (succès et échecs) avec IP, user-agent, timestamp.",
            "Définir des alertes sur : 5+ échecs de login / minute, accès à des chemins sensibles, erreurs 500.",
            "Tester régulièrement les alertes de sécurité (red team exercises).",
        ],
        weight=3.0,
        cwe_references=["CWE-117", "CWE-223", "CWE-532"],
        cvss_ceiling=_cvss_max(a09_all),
    ))

    # --- A10 : Server-Side Request Forgery ---
    controls.append(ComplianceControl(
        id="OWASP-A10",
        framework="OWASP Top 10",
        category="SSRF",
        title="A10:2021 — Server-Side Request Forgery (SSRF)",
        requirement=(
            "Les failles SSRF se produisent lorsqu'une application web récupère une ressource distante "
            "sans valider l'URL fournie par l'utilisateur. Cela permet à un attaquant de contraindre "
            "l'application à envoyer des requêtes vers des destinations inattendues, même derrière un pare-feu. "
            "(OWASP Top 10:2021 — Entrée de la communauté, critique dans les architectures cloud/microservices)"
        ),
        status="na",
        score=50,
        evidence=["SSRF non détectable via scan passif — nécessite un test d'intrusion actif."],
        impact=(
            "Dans les environnements cloud (AWS, GCP, Azure), un SSRF peut permettre d'accéder au service "
            "de métadonnées (169.254.169.254) pour voler les tokens IAM et compromettre l'infrastructure "
            "cloud entière (CVSS potentiel : 10.0). Cf. Capital One breach 2019 (SSRF → S3 exfiltration)."
        ),
        remediation=[
            "Valider et assainir toutes les URLs fournies par l'utilisateur.",
            "Désactiver les redirections HTTP si non nécessaires.",
            "Isoler la fonctionnalité de récupération de ressources dans un réseau dédié sans accès interne.",
            "Refuser par défaut les schémas non HTTPS (file://, ftp://, gopher://).",
            "Implémenter une liste blanche des domaines autorisés pour les requêtes sortantes.",
            "Effectuer un pentest spécifique SSRF sur toutes les fonctionnalités de fetch/proxy.",
        ],
        weight=3.0,
        cwe_references=["CWE-918"],
        cvss_ceiling=None,
    ))

    # Score global OWASP
    counted = [c for c in controls if c.status != "na"]
    total_weight = sum(c.weight for c in counted)
    weighted_score = sum(c.score * c.weight for c in counted)
    overall = round(weighted_score / total_weight, 1) if total_weight else 0.0

    passed = sum(1 for c in controls if c.status == "pass")
    failed = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    na = sum(1 for c in controls if c.status == "na")

    critical_gaps = [c.title for c in controls if c.status == "fail"]
    partial_gaps = [c.title for c in controls if c.status == "partial"]

    statement = (
        f"Sur les {len(controls) - na} contrôles OWASP Top 10 évaluables, {passed} sont satisfaits "
        f"({failed} en échec, {partial} partiellement conformes). "
        f"Score de conformité global : {overall:.0f}/100."
    )
    if critical_gaps:
        statement += f" Lacunes critiques : {', '.join(critical_gaps)}."

    return FrameworkReport(
        framework="OWASP Top 10",
        version="2021",
        overall_score=overall,
        grade=_grade(overall),
        total_controls=len(controls),
        passed=passed, failed=failed, partial=partial, na=na,
        controls=controls,
        critical_gaps=critical_gaps + partial_gaps,
        compliance_statement=statement,
    )


# ---------------------------------------------------------------------------
# PCI-DSS v4.0
# ---------------------------------------------------------------------------

def _evaluate_pci(findings: List[Finding]) -> FrameworkReport:
    controls: List[ComplianceControl] = []

    # --- PCI 2.2 : System configuration standards ---
    defaults = _has_title(findings, "version", "logiciel", "server", "phpinfo", "banner")
    if defaults:
        s, sc = "partial", 50
    else:
        s, sc = "pass", 100

    controls.append(ComplianceControl(
        id="PCI-2.2",
        framework="PCI-DSS v4.0",
        category="Sécurité du système",
        title="Req. 2.2 — Configurations système sécurisées",
        requirement=(
            "PCI-DSS v4.0 Req. 2.2 : Développer des normes de configuration pour tous les composants "
            "du système. Ces normes doivent répondre à toutes les vulnérabilités de sécurité connues "
            "et être cohérentes avec les normes de renforcement des systèmes (CIS Benchmarks, NIST)."
        ),
        status=s, score=sc,
        evidence=_evidence_from(defaults) or ["Aucune configuration par défaut risquée détectée."],
        impact=(
            "Les configurations par défaut non modifiées sont la première cible des scanners automatisés. "
            "La révélation de versions logicielles permet à un attaquant de cibler précisément des CVE "
            "exploitables. Non-conformité PCI → amende potentielle + audit on-site obligatoire."
        ),
        remediation=[
            "Supprimer ou désactiver toutes les fonctionnalités, composants et services inutilisés.",
            "Masquer les versions dans tous les headers HTTP (ServerTokens Prod, expose_php Off).",
            "Appliquer les CIS Benchmarks pour chaque composant (Apache, Nginx, MySQL, etc.).",
            "Documenter et approuver toutes les dérogations aux standards de configuration.",
        ],
        weight=3.0,
    ))

    # --- PCI 4.2.1 : Chiffrement fort en transit ---
    tls_issues = _has_category(findings, "A02")
    if any(f.severity == "critical" for f in tls_issues):
        s, sc = "fail", 0
    elif tls_issues:
        s, sc = "partial", 30
    else:
        s, sc = "pass", 100

    controls.append(ComplianceControl(
        id="PCI-4.2.1",
        framework="PCI-DSS v4.0",
        category="Chiffrement",
        title="Req. 4.2.1 — Chiffrement fort des données en transit",
        requirement=(
            "PCI-DSS v4.0 Req. 4.2.1 : Utiliser une cryptographie forte (TLS 1.2 minimum, TLS 1.3 recommandé) "
            "pour protéger les données de titulaires de carte pendant la transmission sur des réseaux ouverts "
            "et publics. TLS 1.0 et 1.1 sont explicitement interdits depuis le 30 juin 2018."
        ),
        status=s, score=sc,
        evidence=_evidence_from(tls_issues) or ["TLS correctement configuré."],
        impact=(
            "La transmission de données de carte en clair ou via TLS obsolète expose les données "
            "de paiement à l'interception (violation PCI-DSS de niveau critique). "
            "Sanction : amende 5 000–100 000 $/mois, révocation de la capacité à accepter les paiements Visa/Mastercard."
        ),
        remediation=[
            "Désactiver TLS 1.0 et 1.1 immédiatement sur tous les terminaux.",
            "Configurer TLS 1.2 avec suites de chiffrement AEAD uniquement (AES-GCM, ChaCha20-Poly1305).",
            "Activer TLS 1.3 pour les nouvelles connexions.",
            "Vérifier la conformité avec SSL Labs — viser grade A ou A+.",
            "Documenter la politique de chiffrement dans le Security Policy obligatoire PCI.",
        ],
        weight=5.0,
    ))

    # --- PCI 6.4.1/6.4.2 : Protection WAF ---
    sqli = _has_title(findings, "injection sql")
    xss = _has_title(findings, "xss")
    no_rate = _has_title(findings, "rate limiting")
    waf_findings = sqli + xss + no_rate

    if sqli or xss:
        s, sc = "fail", 0
    elif no_rate:
        s, sc = "partial", 50
    else:
        s, sc = "pass", 100

    controls.append(ComplianceControl(
        id="PCI-6.4.2",
        framework="PCI-DSS v4.0",
        category="Applications web",
        title="Req. 6.4.1/6.4.2 — Protection des applications web publiques",
        requirement=(
            "PCI-DSS v4.0 Req. 6.4.1 : Les applications web publiques doivent être protégées contre "
            "les attaques connues. Req. 6.4.2 : Déployer une solution de détection/prévention automatisée "
            "contre les attaques (WAF) configurée pour bloquer ou générer des alertes sur les attaques web. "
            "Cette exigence est obligatoire depuis PCI-DSS v4.0 (mars 2024)."
        ),
        status=s, score=sc,
        evidence=_evidence_from(waf_findings) or ["Aucune injection ou XSS détecté."],
        impact=(
            "Une injection SQL sur une application de paiement permet l'extraction de données de carte "
            "(PAN, CVV, dates d'expiration) de toute la base de données. "
            "Violation PCI → notification obligatoire des marques de carte, investigation forensique "
            "obligatoire par un PCI Forensic Investigator (PFI), amendes jusqu'à 500 000 $."
        ),
        remediation=[
            "Déployer un WAF (Cloudflare, AWS WAF, ModSecurity) avec règles OWASP CRS activées.",
            "Corriger toutes les injections SQL identifiées en utilisant des requêtes préparées.",
            "Corriger toutes les vulnérabilités XSS et implémenter une CSP stricte.",
            "Documenter la solution WAF dans le rapport de conformité PCI SAQ/ROC.",
        ],
        weight=5.0,
    ))

    # --- PCI 7.1 : Contrôle d'accès ---
    access_issues = _has_category(findings, "A01")
    s = "fail" if any(f.severity == "critical" for f in access_issues) else ("partial" if access_issues else "pass")
    sc = 0 if s == "fail" else (50 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="PCI-7.1",
        framework="PCI-DSS v4.0",
        category="Contrôle d'accès",
        title="Req. 7.1 — Limitation d'accès aux composants système",
        requirement=(
            "PCI-DSS v4.0 Req. 7.1 : Les processus et mécanismes de limitation de l'accès aux "
            "composants système et aux données de titulaires de carte sont définis et compris. "
            "Principe du moindre privilège : n'accorder l'accès qu'aux seules personnes qui en ont besoin."
        ),
        status=s, score=sc,
        evidence=_evidence_from(access_issues) or ["Contrôle d'accès correctement configuré."],
        impact=(
            "Un accès non restreint aux composants système (CORS wildcard, méthodes HTTP non sécurisées) "
            "viole le principe du moindre privilège obligatoire PCI. "
            "Risque de fuite de données de paiement via des requêtes cross-origin malveillantes."
        ),
        remediation=[
            "Définir et documenter la matrice des accès pour chaque composant système.",
            "Restreindre CORS aux origines explicitement autorisées.",
            "Désactiver les méthodes HTTP non nécessaires (PUT, DELETE) sur les endpoints exposés.",
            "Segmenter le réseau pour isoler l'environnement porteur de données (CDE).",
        ],
        weight=4.0,
    ))

    # --- PCI 8.2 : Identification & authentification ---
    auth_weak = _has_title(findings, "ftp", "anonyme", "httponly", "webmin", "phpmyadmin")
    s = "fail" if any(f.severity in ("critical", "high") for f in auth_weak) else ("partial" if auth_weak else "pass")
    sc = 0 if s == "fail" else (50 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="PCI-8.2",
        framework="PCI-DSS v4.0",
        category="Authentification",
        title="Req. 8.2 — Identification unique des utilisateurs",
        requirement=(
            "PCI-DSS v4.0 Req. 8.2 : Tous les utilisateurs disposent d'un identifiant unique (ID) "
            "avant de leur permettre d'accéder aux composants système ou aux données de titulaires de carte. "
            "Req. 8.4 : L'authentification multi-facteurs (MFA) est requise pour tout accès non-console "
            "à l'environnement porteur de données (CDE) et pour les accès administratifs."
        ),
        status=s, score=sc,
        evidence=_evidence_from(auth_weak) or ["Aucune défaillance d'authentification détectée."],
        impact=(
            "Le FTP anonyme permet un accès non authentifié aux données — violation directe du Req.8. "
            "Les interfaces d'administration exposées sans MFA sont des vecteurs d'attaque critiques "
            "pour l'accès aux données de paiement."
        ),
        remediation=[
            "Désactiver le FTP anonyme — migrer vers SFTP avec authentification par certificat.",
            "Implémenter MFA sur toutes les interfaces d'administration.",
            "Restreindre l'accès aux interfaces admin par IP (whitelist).",
            "Documenter la politique d'authentification dans le registre des risques PCI.",
        ],
        weight=4.0,
    ))

    # --- PCI 10.2 : Journalisation ---
    log_exp = _has_title(findings, "log", "error.log")
    s = "fail" if log_exp else "pass"
    sc = 0 if log_exp else 100

    controls.append(ComplianceControl(
        id="PCI-10.2",
        framework="PCI-DSS v4.0",
        category="Audit et journalisation",
        title="Req. 10.2 — Journalisation des accès et événements de sécurité",
        requirement=(
            "PCI-DSS v4.0 Req. 10.2 : Mettre en œuvre des journaux d'audit pour reconstruire les événements. "
            "Req. 10.5 : Conserver les journaux d'audit pendant 12 mois minimum (3 mois immédiatement disponibles). "
            "Les logs doivent être protégés contre toute modification et accessible uniquement aux personnes autorisées."
        ),
        status=s, score=sc,
        evidence=_evidence_from(log_exp) or ["Fichiers de log non exposés publiquement."],
        impact=(
            "Des fichiers de log publics exposent l'architecture interne, les stack traces avec chemins "
            "de fichiers et potentiellement des tokens de session. "
            "Non-conformité Req.10 → impossibilité de prouver la traçabilité lors d'un audit PCI QSA."
        ),
        remediation=[
            "Restreindre l'accès à tous les fichiers de log (chmod 640, .htaccess Deny from all).",
            "Centraliser les logs dans un SIEM avec accès contrôlé par rôle.",
            "Configurer des alertes sur les accès non autorisés aux logs.",
            "Implémenter un système de détection d'intégrité des logs (HMAC, timestamps signés).",
        ],
        weight=3.0,
    ))

    # --- PCI 11.3 : Scans de vulnérabilité ---
    controls.append(ComplianceControl(
        id="PCI-11.3",
        framework="PCI-DSS v4.0",
        category="Tests de sécurité",
        title="Req. 11.3 — Scans de vulnérabilité internes et externes",
        requirement=(
            "PCI-DSS v4.0 Req. 11.3.1 : Effectuer des scans de vulnérabilité internes trimestriels. "
            "Req. 11.3.2 : Effectuer des scans externes trimestriels via un ASV (Approved Scanning Vendor). "
            "Req. 11.3.1.1 : Résoudre toutes les vulnérabilités de sévérité haute ou critique. "
            "Req. 11.4 : Effectuer des tests d'intrusion annuels ou après changements significatifs."
        ),
        status="pass",
        score=100,
        evidence=["Ce scan SuturaSec constitue une preuve de conformité au Req. 11.3."],
        impact=(
            "L'absence de scans réguliers ne permet pas de détecter les nouvelles vulnérabilités. "
            "PCI exige la documentation des scans et la preuve de remédiation pour chaque cycle trimestriel."
        ),
        remediation=[
            "Planifier des scans automatiques trimestriels (cron SuturaSec).",
            "Conserver les rapports de scan comme preuve d'audit PCI.",
            "Soumettre les scans externes à un ASV certifié PCI SSC.",
            "Documenter le plan de remédiation pour chaque finding haute/critique.",
        ],
        weight=4.0,
    ))

    # --- PCI 12.6 : Sensibilisation à la sécurité ---
    controls.append(ComplianceControl(
        id="PCI-12.6",
        framework="PCI-DSS v4.0",
        category="Politique de sécurité",
        title="Req. 12.6 — Programme de sensibilisation à la sécurité",
        requirement=(
            "PCI-DSS v4.0 Req. 12.6 : Un programme formel de sensibilisation à la sécurité est en place "
            "pour sensibiliser le personnel à la politique de sécurité de l'information de l'entité. "
            "Formation obligatoire à l'embauche et annuellement pour tous les employés."
        ),
        status="na",
        score=50,
        evidence=["Non évaluable par scan technique — nécessite audit organisationnel."],
        impact=(
            "95% des violations de données impliquent une erreur humaine (Verizon DBIR 2024). "
            "Un programme de sensibilisation réduit le risque de phishing, d'ingénierie sociale et "
            "de mauvaise manipulation des données de paiement."
        ),
        remediation=[
            "Déployer un programme de formation annuelle (KnowBe4, Proofpoint Security Awareness).",
            "Inclure des simulations de phishing trimestrielles.",
            "Former spécifiquement aux risques PCI : gestion des PANs, procédures de breach.",
        ],
        weight=2.0,
    ))

    counted = [c for c in controls if c.status != "na"]
    total_weight = sum(c.weight for c in counted)
    weighted_score = sum(c.score * c.weight for c in counted)
    overall = round(weighted_score / total_weight, 1) if total_weight else 0.0

    passed = sum(1 for c in controls if c.status == "pass")
    failed = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    na = sum(1 for c in controls if c.status == "na")

    critical_gaps = [c.title for c in controls if c.status in ("fail", "partial")]
    statement = (
        f"Conformité PCI-DSS v4.0 : {overall:.0f}/100 — {passed}/{len(controls) - na} exigences satisfaites. "
        f"{'Non-conformité critique détectée — traitement URGENT requis.' if failed > 0 else 'Conformité acceptable avec points d amélioration.'}"
    )

    return FrameworkReport(
        framework="PCI-DSS",
        version="v4.0",
        overall_score=overall,
        grade=_grade(overall),
        total_controls=len(controls),
        passed=passed, failed=failed, partial=partial, na=na,
        controls=controls,
        critical_gaps=critical_gaps,
        compliance_statement=statement,
    )


# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A
# ---------------------------------------------------------------------------

def _evaluate_iso27001(findings: List[Finding]) -> FrameworkReport:
    controls: List[ComplianceControl] = []

    # A.8.8 — Gestion des vulnérabilités techniques
    cve_f = _has_title(findings, "cve", "obsolète", "version")
    s = "fail" if any(f.severity in ("critical", "high") for f in cve_f) else ("partial" if cve_f else "pass")
    sc = 0 if s == "fail" else (50 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="ISO-A.8.8",
        framework="ISO 27001:2022",
        category="Gestion des vulnérabilités",
        title="A.8.8 — Gestion des vulnérabilités techniques",
        requirement=(
            "ISO/IEC 27001:2022 Annexe A, Contrôle 8.8 : Des informations sur les vulnérabilités techniques "
            "des systèmes d'information utilisés doivent être obtenues en temps opportun, l'exposition de "
            "l'organisation à ces vulnérabilités doit être évaluée et des mesures appropriées doivent être prises."
        ),
        status=s, score=sc,
        evidence=_evidence_from(cve_f) or ["Aucun composant vulnérable connu identifié."],
        impact=(
            "La non-conformité à A.8.8 expose l'organisation à des exploits automatisés sur des CVE connues. "
            "Lors d'un audit ISO 27001, ce contrôle est systématiquement vérifié — une non-conformité "
            "peut entraîner le refus de certification ou une non-conformité majeure."
        ),
        remediation=[
            "Mettre en place un processus de veille CVE (NVD feeds, vendor security bulletins).",
            "Définir des SLA de remédiation : critique < 24h, haute < 72h, moyenne < 30 jours.",
            "Utiliser des outils SAST/DAST et SCA dans le pipeline CI/CD.",
            "Documenter le processus dans la politique de gestion des vulnérabilités (obligatoire ISO).",
        ],
        weight=5.0,
    ))

    # A.8.9 — Gestion de la configuration
    config_f = _has_title(findings, "configuration", "version", "phpinfo", "défaut")
    s = "partial" if config_f else "pass"
    sc = 50 if config_f else 100

    controls.append(ComplianceControl(
        id="ISO-A.8.9",
        framework="ISO 27001:2022",
        category="Gestion de la configuration",
        title="A.8.9 — Gestion de la configuration",
        requirement=(
            "ISO/IEC 27001:2022 Annexe A, Contrôle 8.9 : Les configurations, y compris les configurations "
            "de sécurité, du matériel, des logiciels, des services et des réseaux, doivent être établies, "
            "documentées, mises en œuvre, surveillées et revues. Les configurations non sécurisées par défaut "
            "doivent être identifiées et corrigées."
        ),
        status=s, score=sc,
        evidence=_evidence_from(config_f) or ["Configuration correctement gérée."],
        impact=(
            "Des configurations par défaut non modifiées permettent aux attaquants d'utiliser des "
            "dictionnaires de credentials par défaut et des exploits standardisés. "
            "CIS Benchmarks documentent les configurations sécurisées recommandées pour chaque composant."
        ),
        remediation=[
            "Appliquer les CIS Benchmarks (cis-cat.cisecurity.org) pour tous les composants.",
            "Documenter la configuration de référence (baseline) pour chaque système.",
            "Automatiser la vérification de conformité de configuration (Ansible, Chef InSpec).",
            "Revoir et approuver formellement toute dérogation aux standards de configuration.",
        ],
        weight=3.0,
    ))

    # A.8.20 — Sécurité des réseaux
    net_f = _has_category(findings, "A01", "A05") + _has_title(findings, "telnet", "ftp", "snmp", "smb")
    net_crit = [f for f in net_f if f.severity in ("critical", "high")]
    s = "fail" if net_crit else ("partial" if net_f else "pass")
    sc = 0 if s == "fail" else (40 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="ISO-A.8.20",
        framework="ISO 27001:2022",
        category="Sécurité réseau",
        title="A.8.20/A.8.21 — Sécurité des réseaux et services réseau",
        requirement=(
            "ISO/IEC 27001:2022 Annexe A, Contrôle 8.20 : Les réseaux et les équipements réseau doivent être "
            "sécurisés, gérés et contrôlés pour protéger les informations dans les systèmes et les applications. "
            "A.8.21 : Les mécanismes de sécurité, les niveaux de service et les exigences de gestion de "
            "tous les services réseau doivent être identifiés et inclus dans les accords de services réseau."
        ),
        status=s, score=sc,
        evidence=_evidence_from(net_crit[:3]) or _evidence_from(net_f[:3]) or ["Aucune exposition réseau critique."],
        impact=(
            "Les protocoles non chiffrés (Telnet, FTP, SNMP v1/v2) transmettent credentials et données en clair. "
            "SMB exposé publiquement est le vecteur de propagation des ransomwares les plus destructeurs "
            "(WannaCry, NotPetya — pertes estimées > 10 milliards $)."
        ),
        remediation=[
            "Désactiver Telnet, FTP, SNMP v1/v2 — remplacer par SSH, SFTP, SNMP v3.",
            "Bloquer SMB (port 445) sur toute interface exposée publiquement via firewall.",
            "Segmenter le réseau en zones (DMZ, interne, production) avec contrôle strict du flux.",
            "Implémenter un IDS/IPS pour détecter les scans et tentatives d'intrusion.",
            "Réaliser des audits de firewall trimestriels.",
        ],
        weight=4.0,
    ))

    # A.8.24 — Utilisation de la cryptographie
    crypto_f = _has_category(findings, "A02")
    s = "fail" if any(f.severity in ("critical", "high") for f in crypto_f) else ("partial" if crypto_f else "pass")
    sc = 0 if s == "fail" else (45 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="ISO-A.8.24",
        framework="ISO 27001:2022",
        category="Cryptographie",
        title="A.8.24 — Utilisation de la cryptographie",
        requirement=(
            "ISO/IEC 27001:2022 Annexe A, Contrôle 8.24 : Des règles relatives à l'utilisation efficace "
            "de la cryptographie, y compris la gestion des clés cryptographiques, doivent être définies "
            "et mises en œuvre. Cela inclut le choix des algorithmes, longueurs de clé et protocoles "
            "conformes aux recommandations NIST/ANSSI en vigueur."
        ),
        status=s, score=sc,
        evidence=_evidence_from(crypto_f) or ["Chiffrement correctement configuré."],
        impact=(
            "L'utilisation d'algorithmes obsolètes (MD5, SHA1, RC4, DES, TLS 1.0/1.1) constitue une "
            "non-conformité A.8.24. Les données chiffrées avec RC4 sont déchiffrables en temps réel. "
            "L'ANSSI (France) a publié des recommandations explicites (RGS) sur les algorithmes admissibles."
        ),
        remediation=[
            "Adopter TLS 1.3 avec ECDHE + AES-256-GCM comme suite de chiffrement prioritaire.",
            "Renouveler les certificats expirés via une PKI de confiance (Let's Encrypt, DigiCert).",
            "Documenter la politique de cryptographie incluant la gestion du cycle de vie des clés.",
            "Appliquer les recommandations ANSSI (guides.ssi.gouv.fr) pour les algorithmes cryptographiques.",
        ],
        weight=4.0,
    ))

    # A.8.25/A.8.28 — Développement sécurisé
    inj_f = _has_category(findings, "A03") + _has_title(findings, "xss", "injection")
    s = "fail" if inj_f else "pass"
    sc = 0 if inj_f else 100

    controls.append(ComplianceControl(
        id="ISO-A.8.28",
        framework="ISO 27001:2022",
        category="Développement sécurisé",
        title="A.8.25/A.8.28 — Cycle de développement sécurisé",
        requirement=(
            "ISO/IEC 27001:2022 A.8.25 : Des règles relatives au développement sécurisé de logiciels "
            "et de systèmes doivent être établies et appliquées. A.8.28 : Des principes de codage sécurisé "
            "doivent être appliqués au développement de logiciels. Cela inclut la validation des entrées, "
            "l'encodage des sorties et la gestion sécurisée des sessions."
        ),
        status=s, score=sc,
        evidence=_evidence_from(inj_f) or ["Aucune vulnérabilité d'injection détectée."],
        impact=(
            "La présence d'injections SQL ou XSS prouve l'absence de pratiques de développement sécurisé "
            "(SDL/DevSecOps) — non-conformité directe à A.8.28. "
            "Lors d'un audit ISO, cela constitue une non-conformité majeure."
        ),
        remediation=[
            "Déployer un programme SDL (Secure Development Lifecycle) avec formation obligatoire.",
            "Intégrer SAST (SonarQube, Semgrep) et DAST (OWASP ZAP) dans la pipeline CI/CD.",
            "Effectuer des revues de code sécurité (pair review) sur tout code touchant l'authentification.",
            "Établir une politique de gestion des vulnérabilités en développement (Bug Bounty interne).",
        ],
        weight=4.0,
    ))

    # A.5.23 — Sécurité des services cloud
    cloud_f = _has_title(findings, "docker", "kubernetes", "elasticsearch", "s3")
    s = "fail" if any(f.severity == "critical" for f in cloud_f) else ("partial" if cloud_f else "pass")
    sc = 0 if s == "fail" else (50 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="ISO-A.5.23",
        framework="ISO 27001:2022",
        category="Cloud",
        title="A.5.23 — Sécurité de l'information pour l'utilisation des services cloud",
        requirement=(
            "ISO/IEC 27001:2022 Annexe A, Contrôle 5.23 (NOUVEAU 2022) : Les processus d'acquisition, "
            "d'utilisation, de gestion et de fin de service des services cloud doivent être établis "
            "conformément aux exigences de sécurité de l'information de l'organisation."
        ),
        status=s, score=sc,
        evidence=_evidence_from(cloud_f) or ["Aucune exposition d'infrastructure cloud critique."],
        impact=(
            "Une API Docker exposée sans authentification permet à un attaquant de prendre le contrôle total "
            "de l'hôte (CVSS 10.0). Elasticsearch sans auth expose potentiellement toutes les données indexées "
            "— des milliers de bases MongoDB et ES non protégées ont été effacées par des attaquants (Meow Attack 2020)."
        ),
        remediation=[
            "Protéger l'API Docker derrière TLS mutuel (mTLS) avec certificats clients.",
            "Activer l'authentification sur Elasticsearch, MongoDB, Redis et tous les services cloud.",
            "Appliquer le principe du moindre privilège aux rôles IAM cloud.",
            "Documenter la politique d'utilisation cloud dans le SMSI.",
        ],
        weight=4.0,
    ))

    # A.5.14 — Transfert de l'information
    data_f = _has_title(findings, "cors", "information", "version")
    s = "partial" if data_f else "pass"
    sc = 55 if data_f else 100

    controls.append(ComplianceControl(
        id="ISO-A.5.14",
        framework="ISO 27001:2022",
        category="Transfert d'information",
        title="A.5.14 — Transfert de l'information",
        requirement=(
            "ISO/IEC 27001:2022 A.5.14 : Des règles, procédures ou accords de transfert d'informations "
            "doivent être en place pour tous les types de transfert au sein de l'organisation et avec "
            "des parties externes. Cela inclut le contrôle des origines cross-domain autorisées (CORS)."
        ),
        status=s, score=sc,
        evidence=_evidence_from(data_f) or ["Aucune fuite d'information via transfert non autorisé."],
        impact=(
            "Une politique CORS trop permissive (wildcard) permet à des sites tiers de lire les réponses "
            "de votre API au nom d'un utilisateur authentifié. "
            "Les en-têtes exposant des versions logicielles facilitent le ciblage d'attaques précises."
        ),
        remediation=[
            "Définir une politique CORS explicite avec liste blanche des origines autorisées.",
            "Masquer les versions dans tous les headers de réponse.",
            "Documenter les flux de données cross-domain dans la cartographie des traitements RGPD.",
        ],
        weight=2.0,
    ))

    # A.8.7 — Protection contre les malwares
    malware_f = _has_title(findings, "back orifice", "metasploit", "31337", "4444")
    s = "fail" if malware_f else "pass"
    sc = 0 if malware_f else 100

    controls.append(ComplianceControl(
        id="ISO-A.8.7",
        framework="ISO 27001:2022",
        category="Protection malware",
        title="A.8.7 — Protection contre les logiciels malveillants",
        requirement=(
            "ISO/IEC 27001:2022 A.8.7 : Des mesures de protection contre les logiciels malveillants doivent "
            "être mises en œuvre et soutenues par une sensibilisation appropriée des utilisateurs."
        ),
        status=s, score=sc,
        evidence=_evidence_from(malware_f) or ["Aucun indicateur de compromis (malware/backdoor) détecté."],
        impact=(
            "La détection de ports Back Orifice (31337) ou Metasploit (4444) indique une compromission active "
            "— incident de sécurité immédiat. Notification RGPD obligatoire dans les 72h si données personnelles exposées."
        ),
        remediation=[
            "PRIORITÉ IMMÉDIATE : Isoler le système compromis du réseau.",
            "Effectuer une analyse forensique complète avant tout nettoyage.",
            "Notifier le RSSI, la DPO et potentiellement la CNIL (si données personnelles).",
            "Déployer un EDR (CrowdStrike, SentinelOne) sur tous les endpoints.",
        ],
        weight=5.0,
    ))

    counted = [c for c in controls if c.status != "na"]
    total_weight = sum(c.weight for c in counted)
    weighted_score = sum(c.score * c.weight for c in counted)
    overall = round(weighted_score / total_weight, 1) if total_weight else 0.0

    passed = sum(1 for c in controls if c.status == "pass")
    failed = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    na = sum(1 for c in controls if c.status == "na")

    critical_gaps = [c.title for c in controls if c.status in ("fail", "partial")]
    statement = (
        f"Conformité ISO/IEC 27001:2022 : {overall:.0f}/100 — {passed}/{len(controls)} contrôles conformes. "
        f"{'Certification impossible en l état — non-conformités majeures à corriger.' if failed > 2 else 'Conformité partielle — plan d action requis pour certification.'}"
    )

    return FrameworkReport(
        framework="ISO 27001",
        version="2022",
        overall_score=overall,
        grade=_grade(overall),
        total_controls=len(controls),
        passed=passed, failed=failed, partial=partial, na=na,
        controls=controls,
        critical_gaps=critical_gaps,
        compliance_statement=statement,
    )


# ---------------------------------------------------------------------------
# GDPR / RGPD — Article 32
# ---------------------------------------------------------------------------

def _evaluate_gdpr(findings: List[Finding]) -> FrameworkReport:
    controls: List[ComplianceControl] = []

    # Art. 32.1.a — Chiffrement et pseudonymisation
    crypto_f = _has_category(findings, "A02")
    s = "fail" if any(f.severity in ("critical", "high") for f in crypto_f) else ("partial" if crypto_f else "pass")
    sc = 0 if s == "fail" else (40 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="GDPR-32.1.a",
        framework="GDPR",
        category="Chiffrement",
        title="Art. 32.1.a — Chiffrement et pseudonymisation des données",
        requirement=(
            "RGPD Article 32.1.a : Le responsable du traitement et le sous-traitant mettent en œuvre "
            "les mesures techniques et organisationnelles appropriées afin de garantir un niveau de sécurité "
            "adapté au risque, y compris, selon les besoins, le chiffrement et la pseudonymisation des "
            "données à caractère personnel."
        ),
        status=s, score=sc,
        evidence=_evidence_from(crypto_f) or ["Chiffrement en transit correctement configuré."],
        impact=(
            "La transmission de données personnelles en clair constitue une violation de l'Art.32 RGPD. "
            "En cas de contrôle CNIL ou de violation de données, l'absence de chiffrement entraîne une "
            "présomption de faute grave — amende jusqu'à 20M€ ou 4% du CA mondial (Art.83.4 RGPD)."
        ),
        remediation=[
            "Chiffrer toutes les données personnelles en transit (TLS 1.3) et au repos (AES-256).",
            "Pseudonymiser les données personnelles dans les environnements de test et développement.",
            "Documenter les mesures de chiffrement dans le registre des traitements (Art.30 RGPD).",
            "Réaliser une AIPD (Art.35) pour les traitements à risque élevé.",
        ],
        weight=5.0,
    ))

    # Art. 32.1.b — Confidentialité, intégrité, disponibilité
    access_f = _has_category(findings, "A01") + _has_title(findings, "sensible", "cors")
    headers_f = _has_title(findings, "csp", "x-frame", "hsts")
    cia_f = list({id(f): f for f in access_f + headers_f}.values())

    s = "fail" if any(f.severity == "critical" for f in cia_f) else ("partial" if cia_f else "pass")
    sc = 0 if s == "fail" else (45 if s == "partial" else 100)

    controls.append(ComplianceControl(
        id="GDPR-32.1.b",
        framework="GDPR",
        category="Confidentialité & Intégrité",
        title="Art. 32.1.b — Confidentialité, intégrité et disponibilité",
        requirement=(
            "RGPD Article 32.1.b : Garantir la confidentialité, l'intégrité, la disponibilité et la "
            "résilience constantes des systèmes et des services de traitement. Cela exige des contrôles "
            "d'accès stricts, une protection contre les altérations non autorisées et une disponibilité "
            "garantie pour l'exercice des droits des personnes concernées."
        ),
        status=s, score=sc,
        evidence=_evidence_from(cia_f) or ["Confidentialité et intégrité correctement protégées."],
        impact=(
            "Un accès non autorisé à des données personnelles (fichiers sensibles exposés, CORS wildcard) "
            "constitue une violation de données au sens RGPD Art.4.12. "
            "Obligation de notification CNIL dans les 72h (Art.33) et potentiellement aux personnes concernées (Art.34)."
        ),
        remediation=[
            "Implémenter le contrôle d'accès RBAC (Role-Based Access Control) sur toutes les ressources.",
            "Bloquer l'accès public à tous les fichiers contenant des données personnelles.",
            "Restreindre CORS aux origines légitimes traitant des données personnelles.",
            "Implémenter les en-têtes de sécurité pour protéger l'intégrité des pages (CSP, X-Frame-Options).",
        ],
        weight=5.0,
    ))

    # Art. 32.1.d — Tests et évaluation régulière
    controls.append(ComplianceControl(
        id="GDPR-32.1.d",
        framework="GDPR",
        category="Tests de sécurité",
        title="Art. 32.1.d — Tests et évaluation régulière de l'efficacité",
        requirement=(
            "RGPD Article 32.1.d : Mettre en place un processus de test, d'analyse et d'évaluation réguliers "
            "de l'efficacité des mesures techniques et organisationnelles pour assurer la sécurité du traitement. "
            "Ce contrôle est fondamental — il exige la preuve que les mesures de sécurité sont effectivement testées."
        ),
        status="pass",
        score=100,
        evidence=["Ce scan SuturaSec constitue une preuve de conformité Art.32.1.d RGPD."],
        impact=(
            "L'absence de tests réguliers de sécurité est une non-conformité Art.32.1.d souvent retenue "
            "par la CNIL lors des contrôles. La CNIL exige la démonstration d'une politique de tests documentée."
        ),
        remediation=[
            "Planifier des scans SuturaSec mensuels sur toutes les applications traitant des données personnelles.",
            "Conserver les rapports comme preuve documentaire pour les audits CNIL.",
            "Intégrer les résultats dans le plan de traitement des risques du SMSI.",
            "Nommer un RSSI chargé du suivi des tests de sécurité.",
        ],
        weight=4.0,
    ))

    # Art. 25 — Privacy by Design
    design_f = _has_title(findings, "csp", "rate limiting", "open redirect", "permissions-policy")
    s = "partial" if design_f else "pass"
    sc = 55 if design_f else 100

    controls.append(ComplianceControl(
        id="GDPR-25",
        framework="GDPR",
        category="Privacy by Design",
        title="Art. 25 — Protection des données dès la conception",
        requirement=(
            "RGPD Article 25 : Compte tenu de l'état des connaissances, des coûts de mise en œuvre et "
            "de la nature, de la portée, du contexte et des finalités du traitement ainsi que des risques, "
            "le responsable du traitement met en œuvre les mesures techniques et organisationnelles "
            "appropriées dès la conception (Privacy by Design) et par défaut (Privacy by Default)."
        ),
        status=s, score=sc,
        evidence=_evidence_from(design_f) or ["Architecture respectant le Privacy by Design."],
        impact=(
            "L'absence de mesures Privacy by Design (contrôles de sécurité absents dès la conception) "
            "est une non-conformité Art.25 — la CNIL peut l'invoquer indépendamment d'une violation. "
            "Amendes Art.83.4 : jusqu'à 10M€ ou 2% du CA mondial."
        ),
        remediation=[
            "Intégrer les Privacy Impact Assessments (AIPD/DPIA) dans les projets dès la phase de conception.",
            "Implémenter la minimisation des données par défaut (ne collecter que le nécessaire).",
            "Désactiver par défaut toutes les fonctionnalités non nécessaires au traitement.",
            "Former les développeurs aux principes Privacy by Design (CNIL guides pratiques).",
        ],
        weight=4.0,
    ))

    # Art. 33/34 — Notification de violation
    breach_indicators = _has_title(findings, "back orifice", "metasploit", "blacklist",
                                    "malveillant", "injection sql", "xss réfléchi")
    if breach_indicators:
        b_status, b_score = "fail", 0
        b_evidence = _evidence_from(breach_indicators)
        b_note = "Des findings critiques pourraient constituer une violation de données — notification CNIL potentiellement requise."
    else:
        b_status, b_score = "pass", 100
        b_evidence = ["Aucun indicateur de violation de données active détecté."]
        b_note = "Aucune violation de données immédiate identifiée."

    controls.append(ComplianceControl(
        id="GDPR-33",
        framework="GDPR",
        category="Notification de violation",
        title="Art. 33/34 — Notification de violation de données",
        requirement=(
            "RGPD Art. 33 : En cas de violation de données personnelles, le responsable du traitement "
            "notifie la violation à l'autorité de contrôle (CNIL) dans les meilleurs délais et, si possible, "
            "72 heures au plus tard après en avoir pris connaissance. "
            "Art. 34 : Si la violation est susceptible d'engendrer un risque élevé pour les droits "
            "des personnes, celles-ci doivent également en être informées."
        ),
        status=b_status, score=b_score,
        evidence=b_evidence,
        impact=b_note + (
            " En cas de violation : obligation légale de notification CNIL dans 72h + communication "
            "aux personnes concernées si risque élevé. Défaut de notification : amende Art.83.4 jusqu'à 10M€."
        ),
        remediation=[
            "Établir un plan de réponse aux incidents (IRP) documentant les étapes post-violation.",
            "Désigner un DPO (Délégué à la Protection des Données) si obligatoire.",
            "Préparer les modèles de notification CNIL (formulaire CNIL disponible sur notifications.cnil.fr).",
            "Définir les critères internes de qualification d'une 'violation' (Art.4.12 RGPD).",
            "Tester le plan de réponse aux incidents annuellement via des exercices de simulation.",
        ],
        weight=5.0,
    ))

    # Art. 32 — Évaluation globale des risques
    all_critical = [f for f in findings if f.severity == "critical"]
    risk_s = "fail" if len(all_critical) >= 3 else ("partial" if all_critical else "pass")
    risk_sc = 0 if risk_s == "fail" else (40 if risk_s == "partial" else 100)

    controls.append(ComplianceControl(
        id="GDPR-32.2",
        framework="GDPR",
        category="Évaluation des risques",
        title="Art. 32.2 — Évaluation du niveau de risque approprié",
        requirement=(
            "RGPD Art. 32.2 : Pour évaluer le niveau de sécurité approprié, il est tenu compte en particulier "
            "des risques que présente le traitement, résultant notamment de la destruction, de la perte, "
            "de l'altération, de la divulgation non autorisée de données personnelles transmises, conservées "
            "ou traitées d'une autre manière, ou de l'accès non autorisé à celles-ci, de manière accidentelle ou illicite."
        ),
        status=risk_s, score=risk_sc,
        evidence=_evidence_from(all_critical[:4]) or ["Niveau de risque global acceptable."],
        impact=(
            f"{'Niveau de risque CRITIQUE — ' + str(len(all_critical)) + ' vulnérabilité(s) critique(s) détectée(s) sur des traitements potentiellement porteurs de données personnelles.' if all_critical else 'Niveau de risque maîtrisé selon les findings du scan.'}"
        ),
        remediation=[
            "Cartographier les traitements de données personnelles et les flux associés.",
            "Évaluer le risque résiduel après application des mesures correctives.",
            "Documenter l'analyse de risque dans le registre des traitements (Art.30 RGPD).",
            "Consulter le guide CNIL 'Mesures pour traiter un risque' (cnil.fr).",
        ],
        weight=4.0,
    ))

    counted = [c for c in controls if c.status != "na"]
    total_weight = sum(c.weight for c in counted)
    weighted_score = sum(c.score * c.weight for c in counted)
    overall = round(weighted_score / total_weight, 1) if total_weight else 0.0

    passed = sum(1 for c in controls if c.status == "pass")
    failed = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    na = sum(1 for c in controls if c.status == "na")

    critical_gaps = [c.title for c in controls if c.status in ("fail", "partial")]
    statement = (
        f"Conformité RGPD (Art.32) : {overall:.0f}/100 — {passed}/{len(controls)} exigences satisfaites. "
        f"{'ALERTE : Risque de non-conformité CNIL avec exposition potentielle aux amendes Art.83.' if failed > 0 else 'Conformité partielle — points d amélioration à traiter avant audit CNIL.'}"
    )

    return FrameworkReport(
        framework="GDPR",
        version="Art. 32",
        overall_score=overall,
        grade=_grade(overall),
        total_controls=len(controls),
        passed=passed, failed=failed, partial=partial, na=na,
        controls=controls,
        critical_gaps=critical_gaps,
        compliance_statement=statement,
    )


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def run_compliance_analysis(findings: List[Finding]) -> Dict[str, Any]:
    """
    Lance l'analyse de conformité sur 4 frameworks.
    Retourne un dict JSON-serializable.
    """
    owasp  = _evaluate_owasp(findings)
    pci    = _evaluate_pci(findings)
    iso    = _evaluate_iso27001(findings)
    gdpr   = _evaluate_gdpr(findings)

    reports = [owasp, pci, iso, gdpr]

    def serialize_control(c: ComplianceControl) -> dict:
        return {
            "id": c.id,
            "framework": c.framework,
            "category": c.category,
            "title": c.title,
            "requirement": c.requirement,
            "status": c.status,
            "score": c.score,
            "evidence": c.evidence,
            "impact": c.impact,
            "remediation": c.remediation,
            "weight": c.weight,
            "cwe_references": c.cwe_references,
            "cvss_ceiling": c.cvss_ceiling,
        }

    def serialize_report(r: FrameworkReport) -> dict:
        return {
            "framework": r.framework,
            "version": r.version,
            "overall_score": r.overall_score,
            "grade": r.grade,
            "total_controls": r.total_controls,
            "passed": r.passed,
            "failed": r.failed,
            "partial": r.partial,
            "na": r.na,
            "controls": [serialize_control(c) for c in r.controls],
            "critical_gaps": r.critical_gaps,
            "compliance_statement": r.compliance_statement,
        }

    # Score global multi-framework (pondéré)
    framework_weights = {"OWASP Top 10": 3, "PCI-DSS": 3, "ISO 27001": 2, "GDPR": 3}
    total_fw_weight = sum(framework_weights.values())
    global_score = sum(
        r.overall_score * framework_weights.get(r.framework, 1)
        for r in reports
    ) / total_fw_weight

    return {
        "global_score": round(global_score, 1),
        "global_grade": _grade(global_score),
        "frameworks": [serialize_report(r) for r in reports],
        "summary": (
            f"Analyse de conformité multi-framework terminée. "
            f"Score global : {global_score:.0f}/100 ({_grade(global_score)}). "
            f"OWASP : {owasp.overall_score:.0f} | PCI-DSS : {pci.overall_score:.0f} | "
            f"ISO 27001 : {iso.overall_score:.0f} | RGPD : {gdpr.overall_score:.0f}."
        ),
    }
