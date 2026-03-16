"""
Phase 3 — Network Scanner
Checks : TCP port scan, banner grabbing, service fingerprinting,
         service risk assessment, CVE lookup (NVD API).
"""

import ipaddress
import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

# Réutilisation du type Finding de la Phase 2
from app.scanners.web_scanner import Finding


# ---------------------------------------------------------------------------
# Ports communs à scanner
# ---------------------------------------------------------------------------

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 512, 513, 514, 587, 993, 995, 1080, 1433, 1521,
    2375, 2376, 3000, 3306, 3389, 4243, 4444, 5000, 5432,
    5601, 5900, 6379, 6443, 8000, 8008, 8080, 8443, 8888,
    9200, 9300, 11211, 27017, 27018, 31337,
]

# ---------------------------------------------------------------------------
# Référentiel de services et leurs risques intrinsèques
# ---------------------------------------------------------------------------

# port → (nom, protocole, niveau_risque_si_ouvert, message)
SERVICE_RISKS: Dict[int, Tuple[str, str, str, str]] = {
    21:    ("FTP",            "A02",  "high",     "FTP transmet les données et credentials en clair."),
    22:    ("SSH",            "A07",  "info",     "SSH est ouvert — vérifier la version et l'accès root."),
    23:    ("Telnet",         "A02",  "critical", "Telnet transmet tout en clair, incluant les mots de passe."),
    25:    ("SMTP",           "A05",  "medium",   "SMTP ouvert — vérifier le relayage non autorisé (open relay)."),
    53:    ("DNS",            "A05",  "medium",   "DNS exposé — vérifier si le transfert de zone est autorisé."),
    80:    ("HTTP",           "A02",  "low",      "HTTP non chiffré détecté."),
    110:   ("POP3",           "A02",  "high",     "POP3 transmet les emails et credentials en clair."),
    111:   ("RPCBind",        "A05",  "high",     "RPCBind exposé — surface d'attaque élevée sur les systèmes Unix."),
    135:   ("MSRPC",          "A05",  "high",     "MSRPC exposé — vecteur courant d'exploitation Windows."),
    139:   ("NetBIOS",        "A05",  "high",     "NetBIOS exposé — risque d'énumération et d'attaque SMB."),
    143:   ("IMAP",           "A02",  "high",     "IMAP transmet les emails et credentials en clair."),
    445:   ("SMB",            "A05",  "critical", "SMB exposé — vecteur d'attaque critique (EternalBlue, ransomware)."),
    512:   ("rexec",          "A07",  "critical", "rexec (Berkeley r-services) — authentification faible."),
    513:   ("rlogin",         "A07",  "critical", "rlogin — protocole obsolète sans chiffrement."),
    514:   ("rsh/Syslog",     "A07",  "critical", "rsh permet l'exécution de commandes sans authentification forte."),
    1080:  ("SOCKS Proxy",    "A01",  "high",     "Proxy SOCKS ouvert — potentiellement exploitable comme rebond."),
    1433:  ("MSSQL",          "A01",  "high",     "Base de données MSSQL exposée sur le réseau."),
    1521:  ("Oracle DB",      "A01",  "high",     "Base de données Oracle exposée sur le réseau."),
    2375:  ("Docker API",     "A01",  "critical", "API Docker non sécurisée — permet la prise de contrôle totale de l'hôte."),
    2376:  ("Docker TLS",     "A05",  "medium",   "API Docker TLS — vérifier la validité des certificats clients."),
    3306:  ("MySQL",          "A01",  "high",     "Base de données MySQL exposée sur le réseau."),
    3389:  ("RDP",            "A07",  "high",     "Bureau distant exposé — cible de brute-force et exploits (BlueKeep)."),
    4243:  ("Docker API",     "A01",  "critical", "API Docker (port alternatif) non sécurisée."),
    4444:  ("Metasploit",     "A05",  "critical", "Port associé aux shells Metasploit — potentiel compromis actif."),
    5000:  ("Dev Server",     "A05",  "medium",   "Serveur de développement exposé publiquement."),
    5432:  ("PostgreSQL",     "A01",  "high",     "Base de données PostgreSQL exposée sur le réseau."),
    5601:  ("Kibana",         "A01",  "high",     "Interface Kibana exposée — accès potentiel aux données Elasticsearch."),
    5900:  ("VNC",            "A07",  "critical", "VNC exposé — accès bureau à distance, souvent sans auth forte."),
    6379:  ("Redis",          "A01",  "critical", "Redis exposé — généralement sans authentification par défaut."),
    6443:  ("Kubernetes API", "A01",  "critical", "API Kubernetes exposée — accès potentiel à l'orchestrateur."),
    8080:  ("HTTP-Alt",       "A05",  "medium",   "Serveur HTTP alternatif détecté."),
    8888:  ("Jupyter/Dev",    "A01",  "critical", "Jupyter Notebook souvent sans authentification — RCE possible."),
    9200:  ("Elasticsearch",  "A01",  "critical", "Elasticsearch exposé — accès non authentifié aux données par défaut."),
    9300:  ("Elasticsearch",  "A01",  "high",     "Port cluster Elasticsearch exposé."),
    11211: ("Memcached",      "A01",  "high",     "Memcached exposé sans authentification — fuite de données possible."),
    27017: ("MongoDB",        "A01",  "critical", "MongoDB exposé — sans authentification par défaut sur les anciennes versions."),
    27018: ("MongoDB",        "A01",  "high",     "Port secondaire MongoDB exposé."),
    31337: ("Back Orifice",   "A09",  "critical", "Port Back Orifice — signature de compromis potentiel."),
}

OWASP_CATEGORIES = {
    "A01": "A01 – Broken Access Control",
    "A02": "A02 – Cryptographic Failures",
    "A05": "A05 – Security Misconfiguration",
    "A07": "A07 – Identification and Authentication Failures",
    "A09": "A09 – Security Logging and Monitoring Failures",
}

_DEFAULT_CVSS_NET = {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}

# ---------------------------------------------------------------------------
# Scanner principal
# ---------------------------------------------------------------------------

class NetworkScanner:

    def __init__(self, target: str, timeout: float = 2.0, max_workers: int = 50):
        self.target = target.strip()
        self.timeout = timeout
        self.max_workers = max_workers
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    # Point d'entrée
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        hosts = self._resolve_targets()
        if not hosts:
            self.findings.append(Finding(
                title="Cible réseau invalide",
                severity="info",
                category="A05 – Security Misconfiguration",
                description="Impossible de résoudre ou parser la cible réseau.",
                evidence=self.target,
                remediation="Fournissez une IP, un nom d'hôte ou un CIDR valide (ex: 192.168.1.0/24).",
            ))
            return self.findings

        for host in hosts:
            self._scan_host(host)

        return self.findings

    # ------------------------------------------------------------------
    # Résolution de la cible (IP, hostname, CIDR, plage)
    # ------------------------------------------------------------------

    def _resolve_targets(self) -> List[str]:
        target = self.target

        # CIDR (ex: 192.168.1.0/24)
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
            if len(hosts) > 254:
                # Limite à /24 pour éviter les scans trop longs
                hosts = hosts[:254]
            return [str(h) for h in hosts]
        except ValueError:
            pass

        # Plage simple (ex: 192.168.1.1-20)
        range_match = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", target)
        if range_match:
            prefix = range_match.group(1)
            start = int(range_match.group(2))
            end = int(range_match.group(3))
            return [f"{prefix}{i}" for i in range(start, min(end + 1, start + 254))]

        # Hostname ou IP simple
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except socket.gaierror:
            return []

    # ------------------------------------------------------------------
    # Scan d'un hôte
    # ------------------------------------------------------------------

    def _scan_host(self, host: str):
        # Choix des ports selon la cible
        # Pour un /24, on scanne moins de ports pour rester raisonnable
        ports = COMMON_PORTS

        open_ports = self._port_scan(host, ports)

        if not open_ports and host != self._resolve_targets()[0]:
            return  # Hôte inaccessible dans un réseau, on ignore silencieusement

        if not open_ports:
            self.findings.append(Finding(
                title=f"Aucun port ouvert détecté sur {host}",
                severity="info",
                category="A05 – Security Misconfiguration",
                description="Aucun des ports courants n'a répondu. L'hôte est peut-être protégé par un pare-feu.",
                evidence=f"Ports scannés : {len(ports)}",
                remediation="Vérifiez que la cible est bien en ligne et accessible.",
            ))
            return

        # Rapport des ports ouverts
        open_list = ", ".join(f"{p}/{self._get_service_name(p)}" for p in sorted(open_ports.keys()))
        self.findings.append(Finding(
            title=f"Ports ouverts détectés sur {host}",
            severity="info",
            category="A05 – Security Misconfiguration",
            description=f"{len(open_ports)} port(s) ouverts détectés.",
            evidence=f"Ports : {open_list}",
            remediation="Fermer tous les ports non nécessaires. Appliquer le principe du moindre privilège réseau.",
        ))

        for port, banner in open_ports.items():
            self._assess_port(host, port, banner)

    # ------------------------------------------------------------------
    # Scan de ports (TCP connect, multi-thread)
    # ------------------------------------------------------------------

    def _port_scan(self, host: str, ports: List[int]) -> Dict[int, str]:
        open_ports: Dict[int, str] = {}

        def probe(port: int) -> Optional[Tuple[int, str]]:
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    banner = self._grab_banner(sock, port)
                    return port, banner
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(probe, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports[result[0]] = result[1]

        return open_ports

    # ------------------------------------------------------------------
    # Banner grabbing
    # ------------------------------------------------------------------

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(self.timeout)

            # Protocoles qui envoient un banner en premier
            passive_banner_ports = {21, 22, 23, 25, 110, 143, 220, 993, 995}
            if port in passive_banner_ports:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                return banner[:300]

            # HTTP
            if port in (80, 8080, 8000, 8008, 8888):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(2048).decode("utf-8", errors="replace").strip()
                return banner[:300]

            # HTTPS — on tente TLS
            if port in (443, 8443):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    tls_sock = ctx.wrap_socket(sock)
                    tls_sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = tls_sock.recv(2048).decode("utf-8", errors="replace").strip()
                    return banner[:300]
                except Exception:
                    return ""

            return ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Évaluation du risque par port
    # ------------------------------------------------------------------

    def _assess_port(self, host: str, port: int, banner: str):
        risk = SERVICE_RISKS.get(port)

        if risk:
            service_name, owasp_key, severity, description = risk
            category = OWASP_CATEGORIES.get(owasp_key, owasp_key)
            cvss = _DEFAULT_CVSS_NET.get(severity, 5.0)

            evidence = f"Port {port}/tcp ouvert sur {host}"
            if banner:
                evidence += f"\nBanner : {banner[:200]}"

            # Checks spéciaux
            extra = self._special_check(host, port, banner, service_name)

            self.findings.append(Finding(
                title=f"{service_name} exposé (port {port}) sur {host}",
                severity=severity,
                category=category,
                description=description + (f" {extra}" if extra else ""),
                evidence=evidence,
                remediation=self._get_remediation(port, service_name),
                cvss_score=cvss,
            ))

            # Lookup CVE si banner contient une version
            version = self._extract_version(banner)
            if version:
                cves = _lookup_cves(service_name, version)
                for cve in cves:
                    self.findings.append(cve)
        else:
            # Port ouvert sans profil de risque — signalement informatif
            self.findings.append(Finding(
                title=f"Port inconnu ouvert : {port}/tcp sur {host}",
                severity="info",
                category="A05 – Security Misconfiguration",
                description=f"Port {port} ouvert. Service non identifié dans la base de référence.",
                evidence=f"Banner : {banner[:200]}" if banner else f"Port {port} ouvert, pas de banner.",
                remediation="Identifier le service, vérifier s'il est nécessaire et sécurisé.",
            ))

    # ------------------------------------------------------------------
    # Checks spéciaux par service
    # ------------------------------------------------------------------

    def _special_check(self, host: str, port: int, banner: str, service: str) -> str:
        # FTP — login anonyme
        if port == 21:
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as s:
                    s.recv(1024)
                    s.send(b"USER anonymous\r\n")
                    r1 = s.recv(1024).decode("utf-8", errors="replace")
                    s.send(b"PASS anonymous@\r\n")
                    r2 = s.recv(1024).decode("utf-8", errors="replace")
                    if "230" in r2:  # 230 = Login successful
                        self.findings.append(Finding(
                            title=f"FTP — Login anonyme autorisé sur {host}",
                            severity="critical",
                            category="A07 – Identification and Authentication Failures",
                            description="Le serveur FTP accepte les connexions anonymes sans authentification.",
                            evidence=f"USER anonymous → {r1.strip()}\nPASS anonymous@ → {r2.strip()}",
                            remediation="Désactiver l'accès FTP anonyme dans la configuration du serveur.",
                            cvss_score=9.1,
                        ))
                        return "Login anonyme autorisé."
            except Exception:
                pass

        # Redis — sans authentification
        if port == 6379:
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as s:
                    s.send(b"PING\r\n")
                    resp = s.recv(64).decode("utf-8", errors="replace")
                    if "+PONG" in resp:
                        return "Accès sans authentification confirmé (réponse PONG)."
            except Exception:
                pass

        # MongoDB — sans auth
        if port == 27017:
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as s:
                    # Envoi d'un message isMaster minimal
                    msg = bytes.fromhex(
                        "3a000000" "01000000" "00000000" "d4070000"
                        "00000000" "61646d69" "6e2e2463" "6d640000"
                        "00000000" "0100000010" "69734d61" "73746572" "0001000000" "00"
                    )
                    s.send(msg)
                    resp = s.recv(128)
                    if resp:
                        return "Connexion MongoDB sans authentification possible."
            except Exception:
                pass

        return ""

    # ------------------------------------------------------------------
    # Utilitaires
    # ------------------------------------------------------------------

    def _get_service_name(self, port: int) -> str:
        risk = SERVICE_RISKS.get(port)
        if risk:
            return risk[0]
        try:
            return socket.getservbyport(port)
        except Exception:
            return "unknown"

    def _extract_version(self, banner: str) -> Optional[str]:
        if not banner:
            return None
        match = re.search(r"([\w/\-]+)[/ ]([\d]+\.[\d]+\.?[\d]*)", banner)
        if match:
            return f"{match.group(1)} {match.group(2)}"
        return None

    @staticmethod
    def _get_remediation(port: int, service: str) -> str:
        remediations = {
            21:    "Désactiver FTP, utiliser SFTP/SCP. Bloquer le port 21 au pare-feu.",
            22:    "Désactiver l'authentification par mot de passe SSH. Utiliser des clés. Changer le port par défaut.",
            23:    "Désactiver Telnet immédiatement. Utiliser SSH à la place.",
            25:    "Restreindre SMTP aux serveurs légitimes. Désactiver l'open relay.",
            53:    "Restreindre les transferts de zone DNS aux serveurs secondaires autorisés.",
            445:   "Bloquer SMB au pare-feu périmétrique. Appliquer les patches MS17-010.",
            1433:  "Restreindre l'accès MSSQL aux applications autorisées. Ne pas exposer sur Internet.",
            2375:  "Désactiver l'API Docker non TLS immédiatement. Utiliser le socket Unix.",
            3306:  "Restreindre MySQL aux connexions locales ou via tunnel SSH.",
            3389:  "Restreindre RDP via VPN. Activer NLA. Appliquer les patches BlueKeep.",
            5432:  "Restreindre PostgreSQL aux connexions locales ou réseau de confiance.",
            5900:  "Désactiver VNC ou protéger avec un mot de passe fort + VPN.",
            6379:  "Activer l'authentification Redis (requirepass). Lier à localhost.",
            8888:  "Protéger Jupyter avec authentification et ne pas exposer publiquement.",
            9200:  "Activer le module Security Elasticsearch. Ne pas exposer sur Internet.",
            27017: "Activer l'authentification MongoDB. Lier à localhost ou réseau privé.",
        }
        return remediations.get(port, f"Fermer le port {port} si le service n'est pas nécessaire. Filtrer au pare-feu.")


# ---------------------------------------------------------------------------
# CVE Lookup — NVD API v2
# ---------------------------------------------------------------------------

def _lookup_cves(service: str, version: str, max_results: int = 3) -> List[Finding]:
    """Interroge l'API NVD pour les CVEs connus du service/version détecté."""
    findings = []
    try:
        keyword = f"{service} {version}"
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=8,
        )
        if resp.status_code != 200:
            return findings

        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "Pas de description.")
            metrics = cve.get("metrics", {})

            # Extraire le score CVSS (v3 préféré, sinon v2)
            cvss_score = None
            severity = "medium"
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    base_severity = cvss_data.get("baseSeverity", "MEDIUM").upper()
                    severity = base_severity.lower() if base_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "medium"
                    break

            findings.append(Finding(
                title=f"{cve_id} — {service} {version}",
                severity=severity,
                category="A06 – Vulnerable and Outdated Components",
                description=desc[:400],
                evidence=f"Service détecté : {service} {version}\nCVE : {cve_id}",
                remediation=f"Mettre à jour {service} vers la dernière version stable. Consulter https://nvd.nist.gov/vuln/detail/{cve_id}",
                cvss_score=cvss_score,
            ))

    except Exception:
        pass  # NVD inaccessible → on continue sans CVE

    return findings
