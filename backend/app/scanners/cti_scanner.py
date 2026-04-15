"""
CTI Scanner — SuturaSec
Threat Intelligence : IP geolocation, ASN, DNSBL blacklists,
domain age (RDAP), DNS records (SPF/DMARC), AbuseIPDB (optionnel).
"""

import re
import socket
import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.scanners.web_scanner import Finding

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_HEADERS = {"User-Agent": _USER_AGENT, "Accept": "application/json"}

# ---------------------------------------------------------------------------
# DNS Blacklists (DNSBL)
# ---------------------------------------------------------------------------

DNSBL_LISTS = [
    ("zen.spamhaus.org",        "Spamhaus ZEN"),
    ("bl.spamcop.net",          "SpamCop"),
    ("dnsbl.sorbs.net",         "SORBS"),
    ("b.barracudacentral.org",  "Barracuda Central"),
    ("dnsbl-1.uceprotect.net",  "UCEPROTECT Level 1"),
    ("cbl.abuseat.org",         "CBL (Composite Blocking List)"),
    ("dnsbl.dronebl.org",       "DroneBL"),
    ("db.wpbl.info",            "WPBL"),
]

# Pays considérés à risque élevé (contexte InfoSec)
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU"}


# ---------------------------------------------------------------------------
# Scanner principal
# ---------------------------------------------------------------------------

class CTIScanner:

    def __init__(self, target: str, timeout: int = 10, abuseipdb_key: str = ""):
        raw = target.strip()
        # Normalise : retire le schéma et le chemin
        clean = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0]
        self.domain = clean
        self.ip: Optional[str] = None
        self.timeout = timeout
        self.abuseipdb_key = abuseipdb_key
        self.findings: List[Finding] = []
        self.threat_intel: Dict[str, Any] = {
            "domain": self.domain,
            "ip": None,
            "geolocation": {},
            "domain_info": {},
            "dns_records": {},
            "blacklists": {"checked": 0, "listed": 0, "hits": []},
            "abuse": {},
            "threat_score": 0.0,
            "risk_level": "info",
        }

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------

    def run(self) -> Tuple[List[Finding], Dict[str, Any]]:
        # Résolution IP
        try:
            self.ip = socket.gethostbyname(self.domain)
            self.threat_intel["ip"] = self.ip
        except socket.gaierror:
            self.findings.append(Finding(
                title="Impossible de résoudre le domaine",
                severity="info",
                category="A05 – Security Misconfiguration",
                description=f"Le domaine '{self.domain}' ne peut pas être résolu en adresse IP.",
                evidence=f"gethostbyname({self.domain}) → échec DNS",
                remediation="Vérifiez que le domaine existe et que la résolution DNS fonctionne.",
            ))
            return self.findings, self.threat_intel

        self._check_geolocation()
        self._check_dns_records()
        self._check_domain_info()
        self._check_dnsbl()
        if self.abuseipdb_key:
            self._check_abuseipdb()
        self._compute_threat_score()

        return self.findings, self.threat_intel

    # ------------------------------------------------------------------
    # 1. Géolocalisation IP + ASN (ip-api.com — gratuit, sans clé)
    # ------------------------------------------------------------------

    def _check_geolocation(self):
        try:
            r = httpx.get(
                f"http://ip-api.com/json/{self.ip}"
                "?fields=status,country,countryCode,region,regionName,city,isp,org,as,timezone,hosting",
                headers=_HEADERS,
                timeout=self.timeout,
            )
            data = r.json()
            if data.get("status") == "success":
                geo = {
                    "country":      data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region":       data.get("regionName", ""),
                    "city":         data.get("city", ""),
                    "isp":          data.get("isp", ""),
                    "org":          data.get("org", ""),
                    "asn":          data.get("as", ""),
                    "timezone":     data.get("timezone", ""),
                    "is_hosting":   data.get("hosting", False),
                }
                self.threat_intel["geolocation"] = geo

                # Alerte pays à risque
                if geo["country_code"] in HIGH_RISK_COUNTRIES:
                    self.findings.append(Finding(
                        title=f"Hébergement dans un pays à risque : {geo['country']}",
                        severity="high",
                        category="A05 – Security Misconfiguration",
                        description=(
                            f"L'IP {self.ip} est hébergée dans un pays fréquemment associé "
                            f"à des activités malveillantes ou soumis à des sanctions ({geo['country']})."
                        ),
                        evidence=f"IP: {self.ip} | Pays: {geo['country']} ({geo['country_code']}) | ASN: {geo['asn']}",
                        remediation="Évaluez la légitimité de cet hébergement. Envisagez un hébergement dans une juridiction de confiance.",
                        cvss_score=7.5,
                    ))

                # Hébergement datacenter (potentiel VPS/bulletproof)
                if geo["is_hosting"]:
                    self.findings.append(Finding(
                        title="IP hébergée dans un datacenter",
                        severity="info",
                        category="A05 – Security Misconfiguration",
                        description="Cette IP appartient à un datacenter ou fournisseur cloud. Trafic potentiellement automatisé.",
                        evidence=f"ip-api.com → hosting: true | ISP: {geo['isp']} | ASN: {geo['asn']}",
                        remediation="Vérifiez l'activité en provenance de cette IP dans vos logs.",
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 2. Enregistrements DNS (A, AAAA, MX, NS, TXT) + SPF + DMARC
    # ------------------------------------------------------------------

    def _check_dns_records(self):
        dns_records: Dict[str, List[str]] = {}

        # A records (IPv4)
        try:
            addrs = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            a_records = list({r[4][0] for r in addrs})
            if a_records:
                dns_records["A"] = a_records
        except Exception:
            pass

        # AAAA records (IPv6)
        try:
            addrs6 = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            aaaa = list({r[4][0] for r in addrs6})
            if aaaa:
                dns_records["AAAA"] = aaaa
        except Exception:
            pass

        # MX, NS, TXT via Google DNS over HTTPS (pas de dépendance dnspython)
        for rec_type in ("MX", "NS", "TXT"):
            try:
                r = httpx.get(
                    f"https://dns.google/resolve?name={self.domain}&type={rec_type}",
                    headers=_HEADERS,
                    timeout=self.timeout,
                )
                answers = r.json().get("Answer", [])
                records = [a.get("data", "").strip('"') for a in answers if a.get("data")]
                if records:
                    dns_records[rec_type] = records
            except Exception:
                pass

        self.threat_intel["dns_records"] = dns_records

        # --- SPF check ---
        txt_records = dns_records.get("TXT", [])
        has_spf = any("v=spf1" in t for t in txt_records)
        if not has_spf:
            self.findings.append(Finding(
                title="SPF absent — domaine spoofable par email",
                severity="medium",
                category="A05 – Security Misconfiguration",
                description=(
                    f"Aucun enregistrement SPF trouvé pour {self.domain}. "
                    "N'importe qui peut envoyer des emails en usurpant ce domaine."
                ),
                evidence=f"TXT records de {self.domain} : {txt_records or 'aucun'}",
                remediation="Ajouter un TXT SPF : v=spf1 include:_spf.votre-domaine.com ~all",
                cvss_score=5.3,
            ))

        # --- DMARC check ---
        try:
            r = httpx.get(
                f"https://dns.google/resolve?name=_dmarc.{self.domain}&type=TXT",
                headers=_HEADERS,
                timeout=self.timeout,
            )
            dmarc_answers = r.json().get("Answer", [])
            has_dmarc = any("v=DMARC1" in a.get("data", "") for a in dmarc_answers)
            if not has_dmarc:
                self.findings.append(Finding(
                    title="DMARC absent — protection anti-phishing insuffisante",
                    severity="medium",
                    category="A05 – Security Misconfiguration",
                    description=(
                        f"Aucune politique DMARC définie pour {self.domain}. "
                        "Sans DMARC, les emails frauduleux passent les filtres anti-spam."
                    ),
                    evidence=f"Aucun enregistrement _dmarc.{self.domain} trouvé.",
                    remediation=f'Ajouter : _dmarc.{self.domain} TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{self.domain}"',
                    cvss_score=5.3,
                ))
        except Exception:
            pass

        # --- Pas de MX = domaine sans email (info utile) ---
        if not dns_records.get("MX"):
            self.findings.append(Finding(
                title="Aucun enregistrement MX — domaine sans serveur mail",
                severity="info",
                category="A05 – Security Misconfiguration",
                description=f"Aucun enregistrement MX trouvé pour {self.domain}.",
                evidence=f"DNS MX lookup pour {self.domain} → vide",
                remediation="Normal si ce domaine n'est pas censé recevoir d'emails.",
            ))

    # ------------------------------------------------------------------
    # 3. Informations domaine via RDAP (gratuit, sans clé)
    # ------------------------------------------------------------------

    def _check_domain_info(self):
        try:
            r = httpx.get(
                f"https://rdap.org/domain/{self.domain}",
                headers=_HEADERS,
                timeout=self.timeout,
            )
            if r.status_code != 200:
                return

            data = r.json()
            domain_info: Dict[str, Any] = {}

            # Registrar
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                domain_info["registrar"] = field[3]
                                break

            # Dates (registration / expiration)
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date_str = event.get("eventDate", "")[:10]
                if "registration" in action:
                    domain_info["creation_date"] = date_str
                    try:
                        created = datetime.datetime.fromisoformat(date_str)
                        domain_info["age_days"] = (datetime.datetime.utcnow() - created).days
                    except Exception:
                        pass
                elif "expiration" in action:
                    domain_info["expiry_date"] = date_str

            domain_info["status"] = data.get("status", [])
            self.threat_intel["domain_info"] = domain_info

            # Alerte domaine très récent
            age = domain_info.get("age_days", 9999)
            if age < 180:
                self.findings.append(Finding(
                    title=f"Domaine récemment créé — {age} jours",
                    severity="high" if age < 30 else "medium",
                    category="A07 – Identification Failures",
                    description=(
                        f"Le domaine {self.domain} a été créé il y a seulement {age} jour(s). "
                        "Les domaines récents sont fréquemment utilisés dans des campagnes de phishing."
                    ),
                    evidence=f"Date de création (RDAP) : {domain_info.get('creation_date', 'inconnue')}",
                    remediation="Vérifiez l'authenticité de ce domaine avant toute interaction.",
                    cvss_score=7.5 if age < 30 else 5.3,
                ))

            # Alerte domaine expirant bientôt (< 30 jours)
            expiry_str = domain_info.get("expiry_date", "")
            if expiry_str:
                try:
                    expiry = datetime.datetime.fromisoformat(expiry_str)
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        self.findings.append(Finding(
                            title="Domaine expiré",
                            severity="critical",
                            category="A07 – Identification Failures",
                            description=f"Le domaine {self.domain} a expiré le {expiry_str}.",
                            evidence=f"Expiry date RDAP : {expiry_str}",
                            remediation="Renouveler le domaine immédiatement pour éviter le hijacking.",
                            cvss_score=9.1,
                        ))
                    elif days_left < 30:
                        self.findings.append(Finding(
                            title=f"Domaine expire dans {days_left} jours",
                            severity="high",
                            category="A07 – Identification Failures",
                            description=f"Le domaine {self.domain} expire le {expiry_str}. Un domaine expiré peut être racheté par un tiers malveillant.",
                            evidence=f"Expiry date RDAP : {expiry_str}",
                            remediation="Renouveler le domaine avant expiration.",
                            cvss_score=7.5,
                        ))
                except Exception:
                    pass

        except Exception:
            pass

    # ------------------------------------------------------------------
    # 4. DNSBL — Blacklists (requêtes DNS, sans API)
    # ------------------------------------------------------------------

    def _check_dnsbl(self):
        if not self.ip:
            return

        # Reverse IP pour lookup DNSBL
        reversed_ip = ".".join(reversed(self.ip.split(".")))
        hits = []
        listed_count = 0

        for dnsbl, name in DNSBL_LISTS:
            lookup = f"{reversed_ip}.{dnsbl}"
            listed = False
            try:
                socket.gethostbyname(lookup)
                listed = True
                listed_count += 1
            except socket.gaierror:
                pass
            hits.append({"name": name, "listed": listed})

        self.threat_intel["blacklists"] = {
            "checked": len(DNSBL_LISTS),
            "listed": listed_count,
            "hits": hits,
        }

        if listed_count > 0:
            listed_names = [h["name"] for h in hits if h["listed"]]
            self.findings.append(Finding(
                title=f"IP présente sur {listed_count} blacklist(s) DNSBL",
                severity="critical" if listed_count >= 3 else "high",
                category="A05 – Security Misconfiguration",
                description=(
                    f"L'IP {self.ip} est référencée dans {listed_count} liste(s) noire(s) DNS. "
                    "Cela indique une activité malveillante passée ou actuelle (spam, malware, botnet)."
                ),
                evidence=f"Listes positives : {', '.join(listed_names)}",
                remediation=(
                    "Contactez votre hébergeur pour investigation. "
                    "Soumettez une demande de délistage auprès des fournisseurs concernés."
                ),
                cvss_score=9.1 if listed_count >= 3 else 7.5,
            ))

    # ------------------------------------------------------------------
    # 5. AbuseIPDB (optionnel — si ABUSEIPDB_API_KEY est configurée)
    # ------------------------------------------------------------------

    def _check_abuseipdb(self):
        try:
            r = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={**_HEADERS, "Key": self.abuseipdb_key},
                params={"ipAddress": self.ip, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
            if r.status_code != 200:
                return

            data = r.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            last_reported = data.get("lastReportedAt", "")
            usage_type = data.get("usageType", "")
            is_tor = data.get("isTor", False)

            self.threat_intel["abuse"] = {
                "confidence_score": abuse_score,
                "total_reports": total_reports,
                "last_reported": last_reported[:10] if last_reported else "",
                "usage_type": usage_type,
                "is_tor": is_tor,
            }

            if abuse_score >= 50:
                self.findings.append(Finding(
                    title=f"IP malveillante — AbuseIPDB score {abuse_score}%",
                    severity="critical" if abuse_score >= 80 else "high",
                    category="A05 – Security Misconfiguration",
                    description=(
                        f"L'IP {self.ip} a un score de confiance d'abus de {abuse_score}% "
                        f"sur AbuseIPDB avec {total_reports} signalement(s) récent(s)."
                    ),
                    evidence=f"Score: {abuse_score}% | Rapports: {total_reports} | Dernier: {last_reported[:10] if last_reported else 'N/A'}",
                    remediation="Bloquez cette IP dans votre firewall ou WAF.",
                    cvss_score=9.8 if abuse_score >= 80 else 7.5,
                ))

            if is_tor:
                self.findings.append(Finding(
                    title="IP identifiée comme nœud de sortie Tor",
                    severity="high",
                    category="A01 – Broken Access Control",
                    description="Cette IP est un nœud Tor, utilisé pour anonymiser le trafic — fréquemment associé à des activités malveillantes.",
                    evidence=f"AbuseIPDB → isTor: true | IP: {self.ip}",
                    remediation="Envisagez de bloquer les nœuds Tor si votre contexte métier le permet.",
                    cvss_score=7.5,
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 6. Calcul du score de menace global (0–10)
    # ------------------------------------------------------------------

    def _compute_threat_score(self):
        weights = {"critical": 4.0, "high": 2.5, "medium": 1.5, "low": 0.5, "info": 0.0}
        score = sum(weights.get(f.severity, 0) for f in self.findings)
        score = min(score, 10.0)

        self.threat_intel["threat_score"] = round(score, 1)
        self.threat_intel["risk_level"] = (
            "critical" if score >= 8 else
            "high"     if score >= 6 else
            "medium"   if score >= 3 else
            "low"      if score >= 1 else
            "info"
        )
