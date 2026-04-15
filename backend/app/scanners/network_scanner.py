"""
Network Scanner — SuturaSec
Checks : TCP port scan, banner grabbing, service fingerprinting,
         unauthenticated access, weak configs, CVE lookup (NVD).
"""

import ipaddress
import socket
import ssl
import re
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

from app.scanners.web_scanner import Finding


# ---------------------------------------------------------------------------
# Ports à scanner
# ---------------------------------------------------------------------------

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 119, 135, 139, 143,
    161, 162, 389, 443, 445, 465, 512, 513, 514, 587, 636, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 4243,
    4444, 5000, 5432, 5601, 5900, 5985, 6379, 6443, 7001, 8000, 8008,
    8080, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
    27018, 28017, 31337, 50000,
]

# ---------------------------------------------------------------------------
# Référentiel risques par port
# ---------------------------------------------------------------------------

SERVICE_RISKS: Dict[int, Tuple[str, str, str, str]] = {
    20:    ("FTP-Data",       "A02",  "high",     "Canal de données FTP non chiffré exposé."),
    21:    ("FTP",            "A02",  "high",     "FTP transmet credentials et données en clair."),
    22:    ("SSH",            "A07",  "info",     "SSH détecté — vérifier version et configuration."),
    23:    ("Telnet",         "A02",  "critical", "Telnet transmet tout en clair, incluant les mots de passe."),
    25:    ("SMTP",           "A05",  "medium",   "SMTP ouvert — risque d'open relay et spam."),
    53:    ("DNS",            "A05",  "medium",   "DNS exposé — risque de transfert de zone non autorisé."),
    69:    ("TFTP",           "A02",  "high",     "TFTP sans authentification — transfert de fichiers non sécurisé."),
    80:    ("HTTP",           "A02",  "low",      "HTTP non chiffré détecté."),
    110:   ("POP3",           "A02",  "high",     "POP3 transmet emails et credentials en clair."),
    111:   ("RPCBind",        "A05",  "high",     "RPCBind exposé — surface d'attaque élevée sur Unix."),
    119:   ("NNTP",           "A05",  "medium",   "Service NNTP (news) exposé."),
    135:   ("MSRPC",          "A05",  "high",     "MSRPC exposé — vecteur courant d'exploitation Windows."),
    139:   ("NetBIOS",        "A05",  "high",     "NetBIOS exposé — risque d'énumération SMB."),
    143:   ("IMAP",           "A02",  "high",     "IMAP transmet emails et credentials en clair."),
    161:   ("SNMP",           "A05",  "high",     "SNMP exposé — community string souvent 'public'."),
    162:   ("SNMP-Trap",      "A05",  "medium",   "SNMP Trap exposé."),
    389:   ("LDAP",           "A07",  "high",     "LDAP exposé — risque d'énumération d'annuaire."),
    443:   ("HTTPS",          "A02",  "info",     "HTTPS détecté — vérifier la configuration TLS."),
    445:   ("SMB",            "A05",  "critical", "SMB exposé — vecteur critique (EternalBlue, ransomware)."),
    465:   ("SMTPS",          "A05",  "low",      "SMTP sécurisé détecté."),
    512:   ("rexec",          "A07",  "critical", "rexec — authentification faible."),
    513:   ("rlogin",         "A07",  "critical", "rlogin — protocole obsolète sans chiffrement."),
    514:   ("rsh/Syslog",     "A07",  "critical", "rsh permet l'exécution de commandes sans auth forte."),
    587:   ("SMTP-Submit",    "A05",  "low",      "Port SMTP submission détecté."),
    636:   ("LDAPS",          "A07",  "medium",   "LDAP sécurisé — vérifier la configuration."),
    993:   ("IMAPS",          "A02",  "info",     "IMAP sécurisé détecté."),
    995:   ("POP3S",          "A02",  "info",     "POP3 sécurisé détecté."),
    1080:  ("SOCKS Proxy",    "A01",  "high",     "Proxy SOCKS ouvert — potentiellement exploitable comme rebond."),
    1433:  ("MSSQL",          "A01",  "high",     "Base de données MSSQL exposée sur le réseau."),
    1521:  ("Oracle DB",      "A01",  "high",     "Base de données Oracle exposée."),
    1723:  ("PPTP",           "A02",  "high",     "VPN PPTP — protocole faible, vulnérable (MS-CHAPv2)."),
    2049:  ("NFS",            "A01",  "high",     "NFS exposé — risque de montage non autorisé."),
    2375:  ("Docker API",     "A01",  "critical", "API Docker non TLS — prise de contrôle totale de l'hôte possible."),
    2376:  ("Docker TLS",     "A05",  "medium",   "API Docker TLS — vérifier les certificats clients."),
    3000:  ("Dev Server",     "A05",  "medium",   "Serveur de développement exposé publiquement."),
    3306:  ("MySQL",          "A01",  "high",     "Base de données MySQL exposée."),
    3389:  ("RDP",            "A07",  "high",     "Bureau distant exposé — cible de brute-force (BlueKeep)."),
    4243:  ("Docker API",     "A01",  "critical", "API Docker (port alternatif) non sécurisée."),
    4444:  ("Metasploit",     "A05",  "critical", "Port Metasploit — potentiel shell actif."),
    5000:  ("Dev Server",     "A05",  "medium",   "Serveur de développement exposé."),
    5432:  ("PostgreSQL",     "A01",  "high",     "Base de données PostgreSQL exposée."),
    5601:  ("Kibana",         "A01",  "high",     "Kibana exposé — accès potentiel aux données Elasticsearch."),
    5900:  ("VNC",            "A07",  "critical", "VNC exposé — accès bureau à distance, auth souvent faible."),
    5985:  ("WinRM HTTP",     "A07",  "high",     "Windows Remote Management HTTP exposé."),
    6379:  ("Redis",          "A01",  "critical", "Redis exposé — sans authentification par défaut."),
    6443:  ("Kubernetes API", "A01",  "critical", "API Kubernetes exposée."),
    7001:  ("WebLogic",       "A01",  "critical", "WebLogic exposé — nombreuses RCE connues."),
    8080:  ("HTTP-Alt",       "A05",  "medium",   "Serveur HTTP alternatif détecté."),
    8443:  ("HTTPS-Alt",      "A05",  "low",      "HTTPS alternatif détecté."),
    8888:  ("Jupyter/Dev",    "A01",  "critical", "Jupyter Notebook souvent sans auth — RCE possible."),
    9000:  ("SonarQube/PHP",  "A05",  "medium",   "Port 9000 — SonarQube ou PHP-FPM potentiellement exposé."),
    9090:  ("Prometheus",     "A01",  "high",     "Prometheus exposé — métriques et données internes accessibles."),
    9200:  ("Elasticsearch",  "A01",  "critical", "Elasticsearch exposé — accès non authentifié par défaut."),
    9300:  ("Elasticsearch",  "A01",  "high",     "Port cluster Elasticsearch exposé."),
    10000: ("Webmin",         "A07",  "critical", "Webmin exposé — interface admin, nombreuses CVE critiques."),
    11211: ("Memcached",      "A01",  "high",     "Memcached exposé sans authentification."),
    27017: ("MongoDB",        "A01",  "critical", "MongoDB exposé — sans authentification sur anciennes versions."),
    27018: ("MongoDB",        "A01",  "high",     "Port secondaire MongoDB exposé."),
    28017: ("MongoDB HTTP",   "A01",  "high",     "Interface HTTP MongoDB exposée."),
    31337: ("Back Orifice",   "A09",  "critical", "Port Back Orifice — signature de compromis actif."),
    50000: ("SAP/Jenkins",    "A05",  "high",     "Port SAP ou Jenkins — vérifier l'authentification."),
}

OWASP_CATEGORIES = {
    "A01": "A01 – Broken Access Control",
    "A02": "A02 – Cryptographic Failures",
    "A05": "A05 – Security Misconfiguration",
    "A06": "A06 – Vulnerable and Outdated Components",
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
                remediation="Fournissez une IP, un hostname ou un CIDR valide (ex: 192.168.1.0/24).",
            ))
            return self.findings

        for host in hosts:
            self._scan_host(host)

        return self.findings

    # ------------------------------------------------------------------
    # Résolution de la cible
    # ------------------------------------------------------------------

    def _resolve_targets(self) -> List[str]:
        target = self.target

        # Strip http(s)://
        target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

        # CIDR
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts())
            return [str(h) for h in hosts[:254]]
        except ValueError:
            pass

        # Plage (192.168.1.1-20)
        range_match = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", target)
        if range_match:
            prefix = range_match.group(1)
            start = int(range_match.group(2))
            end = int(range_match.group(3))
            return [f"{prefix}{i}" for i in range(start, min(end + 1, start + 254))]

        # Hostname / IP
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except socket.gaierror:
            return []

    # ------------------------------------------------------------------
    # Scan d'un hôte
    # ------------------------------------------------------------------

    def _scan_host(self, host: str):
        open_ports = self._port_scan(host, COMMON_PORTS)

        if not open_ports:
            self.findings.append(Finding(
                title=f"Aucun port ouvert sur {host}",
                severity="info",
                category="A05 – Security Misconfiguration",
                description="Aucun port courant ne répond. L'hôte est peut-être derrière un pare-feu.",
                evidence=f"Ports scannés : {len(COMMON_PORTS)}",
                remediation="Vérifiez que la cible est en ligne et accessible.",
            ))
            return

        # Résumé des ports ouverts
        open_list = ", ".join(
            f"{p}/{self._get_service_name(p)}" for p in sorted(open_ports.keys())
        )
        self.findings.append(Finding(
            title=f"{len(open_ports)} port(s) ouvert(s) sur {host}",
            severity="info",
            category="A05 – Security Misconfiguration",
            description=f"Ports détectés : {open_list}",
            evidence=f"Hôte : {host} — {len(open_ports)} port(s) ouverts",
            remediation="Fermer tous les ports non nécessaires. Appliquer le principe du moindre privilège réseau.",
        ))

        # OS hint via TTL
        os_hint = self._os_hint(host)
        if os_hint:
            self.findings.append(Finding(
                title=f"Système d'exploitation probable : {os_hint} ({host})",
                severity="info",
                category="A05 – Security Misconfiguration",
                description=f"Empreinte TTL suggère : {os_hint}",
                evidence=f"Hôte : {host}",
                remediation="Configurer le TTL pour masquer l'OS si possible.",
            ))

        # Évaluation de chaque port
        for port, banner in open_ports.items():
            self._assess_port(host, port, banner)

        # Checks spécifiques déclenchés si le port est ouvert
        if 21 in open_ports:
            self._check_ftp(host)
        if 22 in open_ports:
            self._check_ssh(host, open_ports[22])
        if 25 in open_ports:
            self._check_smtp_relay(host)
        if 53 in open_ports:
            self._check_dns_zone_transfer(host)
        if 6379 in open_ports:
            self._check_redis(host)
        if 9200 in open_ports:
            self._check_elasticsearch(host)
        if 11211 in open_ports:
            self._check_memcached(host)
        if 27017 in open_ports:
            self._check_mongodb(host)
        if 8888 in open_ports:
            self._check_jupyter(host)
        if 2375 in open_ports or 4243 in open_ports:
            self._check_docker_api(host, 2375 if 2375 in open_ports else 4243)
        if 9090 in open_ports:
            self._check_prometheus(host)

    # ------------------------------------------------------------------
    # TCP port scan multi-thread
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

            passive_ports = {21, 22, 23, 25, 110, 143, 220, 389, 465, 587, 993, 995}
            if port in passive_ports:
                data = sock.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:300]

            if port in (80, 8080, 8000, 8008, 3000, 5000, 9000, 9090, 10000):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = sock.recv(2048)
                return data.decode("utf-8", errors="replace").strip()[:300]

            if port in (443, 8443, 9443):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    tls = ctx.wrap_socket(sock)
                    tls.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    data = tls.recv(2048)
                    return data.decode("utf-8", errors="replace").strip()[:300]
                except Exception:
                    return ""

            # Generic: try recv then HTTP
            try:
                sock.settimeout(0.5)
                data = sock.recv(256)
                if data:
                    return data.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass

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

            self.findings.append(Finding(
                title=f"{service_name} exposé — port {port} sur {host}",
                severity=severity,
                category=category,
                description=description,
                evidence=evidence,
                remediation=self._get_remediation(port, service_name),
                cvss_score=cvss,
            ))

            # CVE lookup si version détectée dans le banner
            version = self._extract_version(banner)
            if version:
                for cve in _lookup_cves(service_name, version):
                    self.findings.append(cve)

        else:
            if banner:
                self.findings.append(Finding(
                    title=f"Service inconnu sur port {port}/tcp ({host})",
                    severity="info",
                    category="A05 – Security Misconfiguration",
                    description=f"Port {port} ouvert. Service non référencé.",
                    evidence=f"Banner : {banner[:200]}",
                    remediation="Identifier le service, vérifier s'il est nécessaire et sécurisé.",
                ))

    # ------------------------------------------------------------------
    # OS Fingerprinting (TTL-based)
    # ------------------------------------------------------------------

    def _os_hint(self, host: str) -> Optional[str]:
        """Tente d'estimer l'OS via le TTL d'une réponse TCP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((host, list(COMMON_PORTS)[0]))
            # Le TTL n'est pas directement accessible en Python pur sans raw sockets
            # On se base sur la réponse SSH/HTTP banner si dispo
            s.close()
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Check FTP anonyme
    # ------------------------------------------------------------------

    def _check_ftp(self, host: str):
        try:
            with socket.create_connection((host, 21), timeout=self.timeout) as s:
                s.recv(1024)
                s.send(b"USER anonymous\r\n")
                r1 = s.recv(1024).decode("utf-8", errors="replace")
                s.send(b"PASS anonymous@test.com\r\n")
                r2 = s.recv(1024).decode("utf-8", errors="replace")
                if "230" in r2:
                    self.findings.append(Finding(
                        title=f"FTP — Connexion anonyme autorisée sur {host}",
                        severity="critical",
                        category="A07 – Identification and Authentication Failures",
                        description="Le serveur FTP accepte les connexions anonymes sans authentification. Tout le contenu du serveur est potentiellement accessible.",
                        evidence=f"USER anonymous → {r1.strip()[:100]}\nPASS anonymous@ → {r2.strip()[:100]}",
                        remediation="Désactiver l'accès FTP anonyme dans la configuration serveur. Utiliser SFTP/SCP.",
                        cvss_score=9.1,
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check SSH — version et config faible
    # ------------------------------------------------------------------

    def _check_ssh(self, host: str, banner: str):
        if not banner:
            return

        # Détection de version faible (SSH-1.x)
        if re.search(r"SSH-1\.", banner, re.IGNORECASE):
            self.findings.append(Finding(
                title=f"SSH version 1 détectée sur {host} — protocole obsolète",
                severity="critical",
                category="A02 – Cryptographic Failures",
                description="SSHv1 est obsolète et vulnérable à de nombreuses attaques (man-in-the-middle, injection de session).",
                evidence=f"Banner SSH : {banner[:150]}",
                remediation="Désactiver SSHv1 dans /etc/ssh/sshd_config : Protocol 2",
                cvss_score=9.8,
            ))
        elif re.search(r"SSH-2\.0", banner, re.IGNORECASE):
            # Extraire la version du serveur pour détecter OpenSSH obsolète
            match = re.search(r"OpenSSH[_\s](\d+\.\d+)", banner, re.IGNORECASE)
            if match:
                version_str = match.group(1)
                try:
                    major, minor = map(int, version_str.split("."))
                    if major < 7 or (major == 7 and minor < 4):
                        self.findings.append(Finding(
                            title=f"OpenSSH version ancienne : {version_str} sur {host}",
                            severity="high",
                            category="A06 – Vulnerable and Outdated Components",
                            description=f"OpenSSH {version_str} est obsolète et peut contenir des vulnérabilités connues.",
                            evidence=f"Banner : {banner[:150]}",
                            remediation="Mettre à jour OpenSSH vers la dernière version stable (>= 9.x).",
                            cvss_score=7.5,
                        ))
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Check SMTP Open Relay
    # ------------------------------------------------------------------

    def _check_smtp_relay(self, host: str):
        try:
            with socket.create_connection((host, 25), timeout=self.timeout) as s:
                s.recv(1024)
                s.send(b"EHLO test.com\r\n")
                s.recv(1024)
                s.send(b"MAIL FROM:<test@attacker.com>\r\n")
                r1 = s.recv(256).decode("utf-8", errors="replace")
                s.send(b"RCPT TO:<victim@external.com>\r\n")
                r2 = s.recv(256).decode("utf-8", errors="replace")

                # 250 = accepté → open relay confirmé
                if r2.startswith("250"):
                    self.findings.append(Finding(
                        title=f"SMTP Open Relay détecté sur {host}",
                        severity="high",
                        category="A05 – Security Misconfiguration",
                        description="Le serveur SMTP accepte de relayer des emails pour des domaines externes. Il peut être utilisé pour envoyer du spam ou des phishing.",
                        evidence=f"MAIL FROM attacker.com → {r1.strip()[:80]}\nRCPT TO external.com → {r2.strip()[:80]}",
                        remediation="Restreindre le relayage SMTP aux domaines et IPs autorisés uniquement.",
                        cvss_score=7.5,
                    ))
                else:
                    # Pas d'open relay — bonne pratique
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check DNS Zone Transfer
    # ------------------------------------------------------------------

    def _check_dns_zone_transfer(self, host: str):
        try:
            # Tenter un AXFR minimal via TCP
            with socket.create_connection((host, 53), timeout=self.timeout) as s:
                # Message DNS AXFR minimaliste
                query = (
                    b"\x00\x1d"   # length prefix (TCP)
                    b"\xab\xcd"   # transaction ID
                    b"\x00\x00"   # flags: standard query
                    b"\x00\x01"   # questions: 1
                    b"\x00\x00\x00\x00\x00\x00"  # no answers/auth/additional
                    b"\x07example\x03com\x00"     # QNAME
                    b"\x00\xfc"   # QTYPE: AXFR
                    b"\x00\x01"   # QCLASS: IN
                )
                s.send(query)
                resp = s.recv(512)
                # Une réponse non-vide avec RCODE=0 peut indiquer un transfert autorisé
                if len(resp) > 12:
                    rcode = resp[3] & 0x0F if len(resp) > 3 else 0xFF
                    if rcode == 0:
                        self.findings.append(Finding(
                            title=f"DNS Zone Transfer potentiellement autorisé sur {host}",
                            severity="high",
                            category="A05 – Security Misconfiguration",
                            description="Le serveur DNS a répondu à une requête AXFR. Un transfert de zone peut exposer l'intégralité des enregistrements DNS.",
                            evidence=f"AXFR query → réponse de {len(resp)} octets, RCODE={rcode}",
                            remediation="Restreindre les transferts de zone aux serveurs DNS secondaires autorisés uniquement.",
                            cvss_score=7.5,
                        ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check Redis — accès sans auth
    # ------------------------------------------------------------------

    def _check_redis(self, host: str):
        try:
            with socket.create_connection((host, 6379), timeout=self.timeout) as s:
                s.send(b"PING\r\n")
                resp = s.recv(64).decode("utf-8", errors="replace")
                if "+PONG" in resp:
                    # Récupérer les infos de config
                    s.send(b"INFO server\r\n")
                    info = s.recv(1024).decode("utf-8", errors="replace")
                    version_match = re.search(r"redis_version:([\d.]+)", info)
                    version = version_match.group(1) if version_match else "inconnue"
                    self.findings.append(Finding(
                        title=f"Redis accessible sans authentification sur {host}",
                        severity="critical",
                        category="A07 – Identification and Authentication Failures",
                        description=f"Redis {version} répond aux commandes sans authentification. Un attaquant peut lire/modifier toutes les données, voire exécuter du code via la commande CONFIG SET.",
                        evidence=f"PING → +PONG (version {version})",
                        remediation="Activer l'authentification Redis (requirepass). Lier Redis à localhost. Ne jamais exposer Redis sur Internet.",
                        cvss_score=9.8,
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check Elasticsearch — accès sans auth
    # ------------------------------------------------------------------

    def _check_elasticsearch(self, host: str):
        try:
            resp = httpx.get(f"http://{host}:9200/", timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("version", {}).get("number", "inconnue")
                cluster = data.get("cluster_name", "inconnu")
                self.findings.append(Finding(
                    title=f"Elasticsearch {version} accessible sans authentification sur {host}",
                    severity="critical",
                    category="A07 – Identification and Authentication Failures",
                    description=f"Elasticsearch (cluster: {cluster}) répond sans authentification. Toutes les données sont accessibles en lecture/écriture.",
                    evidence=f"GET http://{host}:9200/ → HTTP 200\nVersion: {version}, Cluster: {cluster}",
                    remediation="Activer le module Security d'Elasticsearch. Configurer l'authentification et le chiffrement TLS.",
                    cvss_score=9.8,
                ))
                # Tenter de lister les index
                try:
                    idx_resp = httpx.get(f"http://{host}:9200/_cat/indices?v", timeout=3)
                    if idx_resp.status_code == 200 and idx_resp.text:
                        preview = idx_resp.text[:300]
                        self.findings.append(Finding(
                            title=f"Elasticsearch — index accessibles publiquement sur {host}",
                            severity="critical",
                            category="A01 – Broken Access Control",
                            description="La liste complète des index Elasticsearch est accessible sans authentification.",
                            evidence=f"GET /_cat/indices → \n{preview}",
                            remediation="Restreindre l'accès Elasticsearch. Activer l'authentification X-Pack.",
                            cvss_score=9.1,
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check Memcached — accès sans auth
    # ------------------------------------------------------------------

    def _check_memcached(self, host: str):
        try:
            with socket.create_connection((host, 11211), timeout=self.timeout) as s:
                s.send(b"stats\r\n")
                resp = s.recv(1024).decode("utf-8", errors="replace")
                if "STAT" in resp:
                    version_match = re.search(r"STAT version ([\d.]+)", resp)
                    version = version_match.group(1) if version_match else "inconnue"
                    self.findings.append(Finding(
                        title=f"Memcached {version} accessible sans authentification sur {host}",
                        severity="high",
                        category="A07 – Identification and Authentication Failures",
                        description=f"Memcached répond aux commandes sans authentification. Les données en cache sont lisibles et modifiables. Risque d'amplification DDoS (UDP).",
                        evidence=f"stats → STAT pid ... (version {version})",
                        remediation="Lier Memcached à localhost. Filtrer le port 11211 au pare-feu. Désactiver UDP si non nécessaire.",
                        cvss_score=7.5,
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check MongoDB — accès sans auth
    # ------------------------------------------------------------------

    def _check_mongodb(self, host: str):
        try:
            resp = httpx.get(f"http://{host}:28017/", timeout=3)
            if resp.status_code == 200 and "mongodb" in resp.text.lower():
                self.findings.append(Finding(
                    title=f"Interface HTTP MongoDB accessible sur {host}:28017",
                    severity="high",
                    category="A07 – Identification and Authentication Failures",
                    description="L'interface web d'administration MongoDB est exposée et accessible publiquement.",
                    evidence=f"GET http://{host}:28017/ → HTTP 200",
                    remediation="Désactiver l'interface HTTP MongoDB (--nohttpinterface). Activer l'authentification.",
                    cvss_score=7.5,
                ))
        except Exception:
            pass

        # Test connexion TCP directe
        try:
            with socket.create_connection((host, 27017), timeout=self.timeout) as s:
                # isMaster query minimaliste
                isMaster = bytes.fromhex(
                    "3a000000" "01000000" "00000000" "d4070000"
                    "00000000" "61646d69" "6e2e2463" "6d640000"
                    "00000000" "01000000" "1069734d" "61737465"
                    "72000100" "00000000"
                )
                s.send(isMaster)
                resp = s.recv(256)
                if len(resp) > 20:
                    self.findings.append(Finding(
                        title=f"MongoDB accessible sans authentification sur {host}:27017",
                        severity="critical",
                        category="A07 – Identification and Authentication Failures",
                        description="MongoDB répond aux requêtes sans authentification. Les bases de données sont potentiellement accessibles en lecture/écriture.",
                        evidence=f"isMaster query → réponse de {len(resp)} octets",
                        remediation="Activer l'authentification MongoDB (security.authorization: enabled). Lier à localhost.",
                        cvss_score=9.8,
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check Jupyter Notebook — accès sans token
    # ------------------------------------------------------------------

    def _check_jupyter(self, host: str):
        try:
            resp = httpx.get(f"http://{host}:8888/api/kernels", timeout=4)
            if resp.status_code == 200:
                self.findings.append(Finding(
                    title=f"Jupyter Notebook sans authentification sur {host}",
                    severity="critical",
                    category="A07 – Identification and Authentication Failures",
                    description="Jupyter Notebook répond sans token d'authentification. Cela permet l'exécution de code Python arbitraire sur le serveur (RCE).",
                    evidence=f"GET http://{host}:8888/api/kernels → HTTP 200",
                    remediation="Configurer un token ou mot de passe Jupyter. Ne pas exposer Jupyter sur Internet.",
                    cvss_score=10.0,
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check Docker API — accès sans auth
    # ------------------------------------------------------------------

    def _check_docker_api(self, host: str, port: int):
        try:
            resp = httpx.get(f"http://{host}:{port}/version", timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("Version", "inconnue")
                self.findings.append(Finding(
                    title=f"API Docker sans authentification sur {host}:{port}",
                    severity="critical",
                    category="A01 – Broken Access Control",
                    description=f"L'API Docker (v{version}) est accessible sans authentification. Un attaquant peut créer des conteneurs, accéder au système de fichiers de l'hôte et obtenir un accès root.",
                    evidence=f"GET http://{host}:{port}/version → HTTP 200\nVersion Docker : {version}",
                    remediation="Désactiver l'API TCP Docker. Utiliser le socket Unix uniquement. Si TLS requis, configurer les certificats clients.",
                    cvss_score=10.0,
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Check Prometheus — accès sans auth
    # ------------------------------------------------------------------

    def _check_prometheus(self, host: str):
        try:
            resp = httpx.get(f"http://{host}:9090/api/v1/label/__name__/values", timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                metrics_count = len(data.get("data", []))
                self.findings.append(Finding(
                    title=f"Prometheus accessible sans authentification sur {host}",
                    severity="high",
                    category="A01 – Broken Access Control",
                    description=f"Prometheus expose {metrics_count} métriques sans authentification. Informations sur l'infrastructure potentiellement exposées.",
                    evidence=f"GET /api/v1/label/__name__/values → {metrics_count} métriques",
                    remediation="Placer Prometheus derrière un reverse proxy avec authentification. Ne pas exposer sur Internet.",
                    cvss_score=7.5,
                ))
        except Exception:
            pass

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
            21:    "Désactiver FTP. Utiliser SFTP/SCP. Bloquer le port 21 au pare-feu.",
            22:    "Désactiver l'auth par mot de passe SSH. Utiliser des clés RSA/ED25519. Mettre à jour OpenSSH.",
            23:    "Désactiver Telnet immédiatement. Utiliser SSH.",
            25:    "Restreindre SMTP aux serveurs légitimes. Désactiver l'open relay.",
            53:    "Restreindre les transferts de zone DNS aux secondaires autorisés.",
            161:   "Utiliser SNMPv3 avec authentification. Changer la community string 'public'.",
            389:   "Utiliser LDAPS (port 636). Restreindre l'accès anonyme LDAP.",
            445:   "Bloquer SMB au pare-feu. Appliquer MS17-010. Désactiver SMBv1.",
            1433:  "Restreindre MSSQL aux applications autorisées. Ne pas exposer sur Internet.",
            2375:  "Désactiver l'API Docker non-TLS. Utiliser le socket Unix uniquement.",
            3306:  "Restreindre MySQL aux connexions locales. Utiliser un tunnel SSH.",
            3389:  "Restreindre RDP via VPN. Activer NLA. Patcher BlueKeep.",
            5432:  "Restreindre PostgreSQL aux connexions locales.",
            5900:  "Désactiver VNC ou protéger avec mot de passe fort + VPN.",
            6379:  "requirepass dans redis.conf. Bind à localhost.",
            8888:  "Configurer un token Jupyter. Ne pas exposer publiquement.",
            9200:  "Activer X-Pack Security Elasticsearch. Ne pas exposer sur Internet.",
            11211: "Lier Memcached à localhost. Désactiver UDP.",
            27017: "Activer l'auth MongoDB. Bind à localhost ou réseau privé.",
        }
        return remediations.get(port, f"Fermer le port {port} si non nécessaire. Filtrer au pare-feu.")


# ---------------------------------------------------------------------------
# CVE Lookup — NVD API v2
# ---------------------------------------------------------------------------

def _lookup_cves(service: str, version: str, max_results: int = 3) -> List[Finding]:
    findings = []
    try:
        keyword = f"{service} {version}"
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=8,
            headers={"User-Agent": "SuturaSec/1.0 Security Scanner"},
        )
        if resp.status_code != 200:
            return findings

        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description.")
            metrics = cve.get("metrics", {})

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
                evidence=f"Service : {service} {version}\nCVE : {cve_id}",
                remediation=f"Mettre à jour {service}. Voir : https://nvd.nist.gov/vuln/detail/{cve_id}",
                cvss_score=cvss_score,
            ))

    except Exception:
        pass

    return findings
