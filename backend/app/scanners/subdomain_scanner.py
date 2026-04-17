"""
Subdomain Enumeration Scanner — SuturaSec
Multi-source, high-confidence subdomain discovery:
  • Certificate Transparency logs (crt.sh)
  • HackerTarget passive DNS API
  • DNS brute-force (400+ wordlist)
  • SPF / MX / NS record extraction
  • DNS Zone Transfer (AXFR) detection
  • Wildcard DNS detection & filtering
  • Concurrent resolution (ThreadPoolExecutor x40)
  • HTTP/HTTPS probing (status, title, server, techs)
  • Subdomain Takeover detection (26 services)
"""

import re
import socket
import threading
import concurrent.futures
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from app.scanners.web_scanner import Finding

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}
_DOH_HEADERS = {"User-Agent": _USER_AGENT, "Accept": "application/json"}

# ---------------------------------------------------------------------------
# Wordlist — 400+ sous-domaines courants
# ---------------------------------------------------------------------------

WORDLIST: List[str] = [
    # Core web
    "www", "www1", "www2", "www3", "web", "web1", "web2", "web3",
    "m", "mobile", "wap", "app", "app1", "app2", "app3",
    # APIs
    "api", "api1", "api2", "api3", "api4", "apis", "gateway", "gw",
    "rest", "graphql", "grpc", "webhook", "webhooks",
    # Email
    "mail", "mail1", "mail2", "mail3", "webmail", "smtp", "smtps",
    "pop", "pop3", "pop3s", "imap", "imaps", "mx", "mx1", "mx2", "mx3",
    "email", "e-mail", "newsletter", "lists", "autoconfig", "autodiscover",
    # DNS / Nameservers
    "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "dns", "dns1", "dns2",
    # Admin / Management
    "admin", "administrator", "admins", "administration",
    "panel", "control", "cp", "controlpanel", "console",
    "dashboard", "manage", "management", "manager", "manager1",
    "webadmin", "sysadmin", "phpmyadmin", "pma", "myadmin", "adminer",
    "plesk", "cpanel", "whm", "webdisk", "directadmin",
    # Auth / Identity
    "auth", "authentication", "login", "logout", "signin", "signup",
    "register", "sso", "oauth", "oauth2", "oidc", "saml", "ldap",
    "identity", "id", "accounts", "account", "password", "reset",
    # Development environments
    "dev", "dev1", "dev2", "develop", "development", "developer", "developers",
    "staging", "stage", "stg", "stg1", "stg2",
    "test", "test1", "test2", "testing", "tst",
    "qa", "uat", "preprod", "pre-prod", "pre",
    "sandbox", "beta", "beta1", "alpha", "demo", "demo1",
    "preview", "nightly", "rc", "lab", "labs",
    "local", "localhost", "int", "integration",
    # Production
    "prod", "production", "live",
    # CDN / Static assets
    "cdn", "cdn1", "cdn2", "static", "assets", "asset",
    "img", "images", "image", "media", "files", "file",
    "upload", "uploads", "download", "downloads", "content",
    "s3", "blob", "storage", "store",
    # CI/CD / DevOps
    "git", "gitlab", "github", "svn", "cvs", "hg",
    "jenkins", "ci", "cd", "cicd", "build", "builds",
    "deploy", "deployment", "deployments", "release",
    "registry", "nexus", "artifactory", "harbor",
    "docker", "k8s", "kubernetes", "helm",
    # Monitoring
    "monitor", "monitoring", "mon", "status", "health", "healthcheck",
    "metrics", "metric", "logs", "log", "analytics",
    "grafana", "kibana", "prometheus", "elastic", "elasticsearch",
    "splunk", "nagios", "zabbix", "netdata", "influx",
    "datadog", "newrelic", "sentry", "jaeger", "zipkin",
    # Databases
    "db", "db1", "db2", "database", "databases",
    "mysql", "postgres", "postgresql", "mongodb", "mongo",
    "redis", "memcached", "cache", "cassandra", "clickhouse",
    # Infrastructure
    "proxy", "lb", "loadbalancer", "load-balancer",
    "firewall", "fw", "vpn", "vpn1", "vpn2", "bastion",
    "jump", "jumphost", "ssh", "rdp", "citrix",
    "server", "server1", "server2", "server3",
    "host", "host1", "host2", "node", "node1", "node2",
    # Backup
    "backup", "backups", "bak", "backup1",
    # Collaboration / Project management
    "jira", "confluence", "wiki", "docs", "doc", "documentation",
    "help", "helpdesk", "support", "ticket", "tickets", "desk",
    "kb", "knowledge", "faq", "community", "forum",
    "chat", "slack", "teams", "zoom", "meet",
    "intranet", "internal", "private",
    # E-commerce / Business
    "shop", "store", "checkout", "cart", "pay", "payment", "payments",
    "billing", "invoice", "invoices", "order", "orders",
    "crm", "erp", "hr", "hrm", "finance", "accounting",
    "sales", "marketing", "portal", "client", "clients",
    "customer", "customers", "partner", "partners",
    "vendor", "vendors", "supplier",
    # Content / Media
    "blog", "news", "press", "media2", "podcast",
    "video", "stream", "streaming", "live",
    "forum2", "social", "community2",
    # Cloud / PaaS
    "cloud", "platform", "paas", "iaas", "saas",
    # Security
    "secure", "ssl", "tls", "waf", "ids", "ips", "siem",
    "vault", "secrets", "keycloak",
    # Misc tools
    "mail-relay", "relay", "office", "remote", "workspace",
    "erp", "crm2",
    # Regional / Geographic
    "us", "eu", "eu1", "eu2", "us-east", "us-west",
    "asia", "apac", "emea", "uk", "fr", "de", "jp", "au",
    # Old/Legacy
    "old", "legacy", "v1", "v2", "v3", "new", "archive",
    "back", "tmp", "temp", "temp1",
    # Numeric
    "1", "2", "3", "4", "5",
    # Tools / Special
    "assets2", "cloud2", "search", "api-gateway", "microservice",
    "ms", "service", "services", "hub", "connect", "connect2",
    "report", "reports", "export", "import", "migrate",
    "feed", "feeds", "rss", "xml", "json", "graphql2",
    "admin2", "portal2", "login2", "signup2",
    "crm3", "erp2", "ops", "devops", "infra", "infrastructure",
]

# ---------------------------------------------------------------------------
# Subdomain Takeover Fingerprints
# (service_name, cname_patterns, body_fingerprints, cvss_score)
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS: List[Tuple[str, List[str], List[str], float]] = [
    ("GitHub Pages",
     [r"\.github\.io$", r"\.github\.com$"],
     ["There isn't a GitHub Pages site here",
      "For root URLs (aka your apex domain)"],
     9.8),

    ("Heroku",
     [r"\.herokudns\.com$", r"\.herokuapp\.com$"],
     ["No such app", "herokucdn.com/error-pages/no-such-app"],
     9.8),

    ("Netlify",
     [r"\.netlify\.app$", r"\.netlify\.com$"],
     ["Not Found - Request ID"],
     9.8),

    ("Vercel",
     [r"\.vercel\.app$"],
     ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found",
      "No deployments found"],
     9.8),

    ("AWS S3",
     [r"\.s3\.amazonaws\.com$", r"\.s3-website[.-]"],
     ["NoSuchBucket", "The specified bucket does not exist",
      "BucketNotFound"],
     9.8),

    ("AWS CloudFront",
     [r"\.cloudfront\.net$"],
     ["ERROR: The request could not be satisfied",
      "Bad request. We can't connect to the server"],
     7.5),

    ("Azure",
     [r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$",
      r"\.azurecontainerapps\.io$"],
     ["404 Web Site not found",
      "Microsoft Azure App Service - Error 404"],
     9.8),

    ("Fastly",
     [r"\.fastly\.net$", r"\.fastlylb\.net$"],
     ["Fastly error: unknown domain",
      "Please check that this domain has been added to a service"],
     9.8),

    ("GitLab Pages",
     [r"\.gitlab\.io$"],
     ["404", "Whoops, looks like something went wrong"],
     7.5),

    ("Shopify",
     [r"\.myshopify\.com$"],
     ["Sorry, this shop is currently unavailable",
      "Only one step away"],
     9.1),

    ("Squarespace",
     [r"\.squarespace\.com$"],
     ["No Such Account"],
     7.5),

    ("Tumblr",
     [r"\.tumblr\.com$"],
     ["There's nothing here",
      "Whatever you were looking for doesn't currently exist"],
     7.5),

    ("WordPress.com",
     [r"\.wordpress\.com$"],
     ["Do you want to register",
      "doesn't exist"],
     7.5),

    ("Ghost",
     [r"\.ghost\.io$"],
     ["The thing you were looking for is no longer here"],
     7.5),

    ("Zendesk",
     [r"\.zendesk\.com$"],
     ["Help Center Closed",
      "Brace yourself"],
     9.1),

    ("Freshdesk",
     [r"\.freshdesk\.com$"],
     ["May be you are looking for"],
     7.5),

    ("Surge.sh",
     [r"\.surge\.sh$"],
     ["project not found"],
     9.1),

    ("Webflow",
     [r"\.webflow\.io$"],
     ["The page you are looking for doesn't exist",
      "No site found for this domain"],
     7.5),

    ("Pantheon",
     [r"\.pantheonsite\.io$", r"\.pantheon\.io$"],
     ["The gods are wise", "404 error unknown site"],
     7.5),

    ("Fly.io",
     [r"\.fly\.dev$"],
     ["404 - Not Found",
      "No application found that matches the host provided"],
     7.5),

    ("Render",
     [r"\.onrender\.com$"],
     ["Not Found - The page you are looking for does not exist",
      "This site can't be reached"],
     7.5),

    ("Read the Docs",
     [r"\.readthedocs\.io$", r"\.readthedocs\.org$"],
     ["unknown to Read the Docs"],
     7.5),

    ("Readme.io",
     [r"\.readme\.io$", r"\.readme\.com$"],
     ["Project doesnt exist yet"],
     7.5),

    ("Intercom",
     [r"\.intercom\.help$"],
     ["This page is reserved"],
     7.5),

    ("WP Engine",
     [r"\.wpengine\.com$"],
     ["The site you were looking for couldn't be found"],
     7.5),

    ("JetBrains Space",
     [r"\.jetbrains\.space$"],
     ["404"],
     7.5),
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SubdomainInfo:
    subdomain: str
    ips: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    https: bool = False
    source: str = "bruteforce"
    takeover_risk: bool = False
    takeover_service: Optional[str] = None


# ---------------------------------------------------------------------------
# Scanner principal
# ---------------------------------------------------------------------------

class SubdomainScanner:

    def __init__(self, target: str, timeout: int = 8,
                 resolve_workers: int = 40, probe_workers: int = 20):
        raw = target.strip()
        clean = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0]
        self.domain = clean.lower().rstrip(".")
        self.timeout = timeout
        self.probe_timeout = 6
        self.resolve_workers = resolve_workers
        self.probe_workers = probe_workers

        self._lock = threading.Lock()
        self.subdomains: Dict[str, SubdomainInfo] = {}
        self.wildcard_ips: Set[str] = set()
        self.wildcard_detected: bool = False
        self.zone_transfer_vuln: bool = False
        self.zone_transfer_servers: List[str] = []
        self.findings: List[Finding] = []

        # Sources accounting
        self._sources: Dict[str, int] = {
            "crtsh": 0, "hackertarget": 0,
            "dns_records": 0, "bruteforce": 0,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> Tuple[List[Finding], Dict[str, Any]]:
        # 1. Wildcard detection
        self._detect_wildcard()

        # 2. Gather candidates from all sources
        source_map: Dict[str, str] = {}

        crtsh_found = self._enumerate_crtsh()
        for s in crtsh_found:
            source_map.setdefault(s, "crt.sh")
        self._sources["crtsh"] = len(crtsh_found)

        ht_found = self._enumerate_hackertarget()
        for s in ht_found:
            source_map.setdefault(s, "hackertarget")
        self._sources["hackertarget"] = len(ht_found)

        dns_found = self._extract_from_dns()
        for s in dns_found:
            source_map.setdefault(s, "dns_records")
        self._sources["dns_records"] = len(dns_found)

        brute_found: Set[str] = set()
        for w in WORDLIST:
            fqdn = f"{w}.{self.domain}"
            brute_found.add(fqdn)
            source_map.setdefault(fqdn, "bruteforce")
        self._sources["bruteforce"] = len(brute_found)

        all_candidates = (crtsh_found | ht_found | dns_found | brute_found)

        # 3. Zone Transfer attempt
        self._check_zone_transfer()

        # 4. Concurrent DNS resolution
        self._resolve_all(all_candidates, source_map)

        # 5. HTTP probing (top 120 subdomains max to keep scan fast)
        to_probe = list(self.subdomains.values())
        # Prioritise: passive sources first, then resolved brute-force
        to_probe.sort(key=lambda s: (
            0 if s.source in ("crt.sh", "hackertarget", "dns_records") else 1,
            s.subdomain
        ))
        self._probe_all(to_probe[:120])

        # 6. Takeover detection (on all probed subdomains)
        self._check_takeovers()

        # 7. Generate findings
        self._generate_findings()

        return self.findings, self._build_recon_data()

    # ------------------------------------------------------------------
    # 1. Wildcard DNS detection
    # ------------------------------------------------------------------

    def _detect_wildcard(self):
        random_sub = f"suturasec-wc-{uuid.uuid4().hex[:10]}.{self.domain}"
        try:
            addrs = socket.getaddrinfo(random_sub, None, socket.AF_INET)
            ips = list({r[4][0] for r in addrs})
            if ips:
                self.wildcard_detected = True
                self.wildcard_ips = set(ips)
        except (socket.gaierror, OSError):
            pass

    # ------------------------------------------------------------------
    # 2a. Certificate Transparency — crt.sh
    # ------------------------------------------------------------------

    def _enumerate_crtsh(self) -> Set[str]:
        found: Set[str] = set()
        queries = [f"%.{self.domain}", self.domain]
        for q in queries:
            try:
                r = httpx.get(
                    f"https://crt.sh/?q={q}&output=json",
                    headers=_DOH_HEADERS,
                    timeout=30,
                )
                if r.status_code != 200:
                    continue
                for entry in r.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().rstrip(".")
                        if name.startswith("*."):
                            name = name[2:]
                        if (name.endswith(f".{self.domain}")
                                and name != self.domain
                                and "*" not in name):
                            found.add(name)
            except Exception:
                pass
        return found

    # ------------------------------------------------------------------
    # 2b. HackerTarget passive DNS
    # ------------------------------------------------------------------

    def _enumerate_hackertarget(self) -> Set[str]:
        found: Set[str] = set()
        try:
            r = httpx.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                headers=_DOH_HEADERS,
                timeout=15,
            )
            if r.status_code == 200 and "error check" not in r.text.lower():
                for line in r.text.strip().splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if (sub.endswith(f".{self.domain}")
                                and sub != self.domain):
                            found.add(sub)
        except Exception:
            pass
        return found

    # ------------------------------------------------------------------
    # 2c. DNS record extraction (MX, NS, TXT/SPF)
    # ------------------------------------------------------------------

    def _extract_from_dns(self) -> Set[str]:
        found: Set[str] = set()

        # MX and NS records often reveal subdomains
        for rec_type in ("MX", "NS"):
            try:
                r = httpx.get(
                    f"https://dns.google/resolve?name={self.domain}&type={rec_type}",
                    headers=_DOH_HEADERS,
                    timeout=self.timeout,
                )
                for a in r.json().get("Answer", []):
                    data = a.get("data", "").strip().rstrip(".")
                    if " " in data:          # MX priority prefix
                        data = data.split(" ", 1)[-1].strip()
                    data = data.lower()
                    if (data.endswith(f".{self.domain}")
                            and data != self.domain):
                        found.add(data)
            except Exception:
                pass

        # SPF record — extract include: sub-domains
        try:
            r = httpx.get(
                f"https://dns.google/resolve?name={self.domain}&type=TXT",
                headers=_DOH_HEADERS,
                timeout=self.timeout,
            )
            for a in r.json().get("Answer", []):
                txt = a.get("data", "")
                for match in re.finditer(
                        r'include:([a-z0-9._-]+\.' + re.escape(self.domain) + r')',
                        txt, re.I):
                    found.add(match.group(1).lower())
        except Exception:
            pass

        return found

    # ------------------------------------------------------------------
    # 3. DNS Zone Transfer (AXFR) attempt
    # ------------------------------------------------------------------

    def _build_axfr_query(self) -> bytes:
        """Build a minimal DNS AXFR query (TCP)."""
        tid = b'\xde\xad'
        flags = b'\x01\x00'   # QR=0, RD=1
        qdcount = b'\x00\x01'
        zero = b'\x00\x00'
        name = b''
        for label in self.domain.split("."):
            enc = label.encode()
            name += bytes([len(enc)]) + enc
        name += b'\x00'
        qtype = b'\x00\xfc'   # AXFR = 252
        qclass = b'\x00\x01'  # IN
        msg = tid + flags + qdcount + zero + zero + zero + name + qtype + qclass
        return len(msg).to_bytes(2, "big") + msg

    def _try_axfr(self, ns_name: str) -> bool:
        try:
            ns_ip = socket.gethostbyname(ns_name)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ns_ip, 53))
            sock.sendall(self._build_axfr_query())
            raw_len = sock.recv(2)
            if len(raw_len) < 2:
                sock.close()
                return False
            resp_len = int.from_bytes(raw_len, "big")
            response = b""
            while len(response) < resp_len:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            # A "REFUSED" response is ≤ 30 bytes; a real zone transfer is large
            if len(response) > 200:
                return True
        except Exception:
            pass
        return False

    def _check_zone_transfer(self):
        ns_list: List[str] = []
        try:
            r = httpx.get(
                f"https://dns.google/resolve?name={self.domain}&type=NS",
                headers=_DOH_HEADERS,
                timeout=self.timeout,
            )
            for a in r.json().get("Answer", []):
                ns = a.get("data", "").strip().rstrip(".")
                if ns:
                    ns_list.append(ns)
        except Exception:
            return

        for ns in ns_list:
            if self._try_axfr(ns):
                self.zone_transfer_vuln = True
                self.zone_transfer_servers.append(ns)

    # ------------------------------------------------------------------
    # 4. Concurrent DNS resolution
    # ------------------------------------------------------------------

    def _resolve_single(self, fqdn: str) -> Optional[Tuple[str, List[str]]]:
        try:
            addrs = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            ips = list({r[4][0] for r in addrs})
            if not ips:
                return None
            # Filter: if all IPs are wildcard IPs, it's a false positive
            if self.wildcard_detected:
                real_ips = [ip for ip in ips if ip not in self.wildcard_ips]
                if not real_ips:
                    return None
            return fqdn, ips
        except (socket.gaierror, OSError):
            return None

    def _resolve_all(self, candidates: Set[str], source_map: Dict[str, str]):
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.resolve_workers) as ex:
            future_to_fqdn = {
                ex.submit(self._resolve_single, fqdn): fqdn
                for fqdn in candidates
            }
            for future in concurrent.futures.as_completed(future_to_fqdn):
                result = future.result()
                if result:
                    fqdn, ips = result
                    src = source_map.get(fqdn, "bruteforce")
                    with self._lock:
                        if fqdn not in self.subdomains:
                            self.subdomains[fqdn] = SubdomainInfo(
                                subdomain=fqdn,
                                ips=ips,
                                source=src,
                            )

    # ------------------------------------------------------------------
    # 5. HTTP / HTTPS probing
    # ------------------------------------------------------------------

    def _probe_single(self, info: SubdomainInfo):
        for scheme in ("https", "http"):
            try:
                r = httpx.get(
                    f"{scheme}://{info.subdomain}",
                    headers=_HEADERS,
                    follow_redirects=True,
                    timeout=self.probe_timeout,
                    verify=False,
                )
                info.status_code = r.status_code
                info.https = (scheme == "https")

                # Title extraction
                body = r.text[:6000]
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                if m:
                    info.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

                # Server header
                info.server = (
                    r.headers.get("server", "")
                    or r.headers.get("x-powered-by", "")
                )[:60]

                # Technology detection
                body_low = body.lower()
                techs = []
                if "wp-content" in body_low or "wp-includes" in body_low:
                    techs.append("WordPress")
                if "joomla" in body_low:
                    techs.append("Joomla")
                if "drupal" in body_low or "x-drupal" in str(r.headers).lower():
                    techs.append("Drupal")
                if "laravel" in body_low:
                    techs.append("Laravel")
                if "django" in body_low:
                    techs.append("Django")
                if "react" in body_low and ("__react" in body_low or "reactdom" in body_low):
                    techs.append("React")
                if "vue" in body_low and ("vue.js" in body_low or "v-app" in body_low):
                    techs.append("Vue.js")
                if "angular" in body_low and "ng-" in body_low:
                    techs.append("Angular")
                if "next.js" in body_low or "__next" in body_low:
                    techs.append("Next.js")
                if "nuxt" in body_low:
                    techs.append("Nuxt.js")
                if "x-shopify" in str(r.headers).lower():
                    techs.append("Shopify")
                info.technologies = techs

                break  # success — no need to try http if https worked
            except Exception:
                pass  # try next scheme

    def _probe_all(self, infos: List[SubdomainInfo]):
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.probe_workers) as ex:
            futures = [ex.submit(self._probe_single, info) for info in infos]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # 6. Subdomain Takeover detection
    # ------------------------------------------------------------------

    def _get_cname(self, fqdn: str) -> Optional[str]:
        try:
            r = httpx.get(
                f"https://dns.google/resolve?name={fqdn}&type=CNAME",
                headers=_DOH_HEADERS,
                timeout=5,
            )
            for a in r.json().get("Answer", []):
                if a.get("type") == 5:   # CNAME record type
                    return a.get("data", "").rstrip(".").lower()
        except Exception:
            pass
        return None

    def _check_takeover_single(self, info: SubdomainInfo):
        cname = self._get_cname(info.subdomain)
        if not cname:
            return
        info.cname = cname

        for service, cname_patterns, body_fps, cvss in TAKEOVER_FINGERPRINTS:
            matched_pattern = False
            for pattern in cname_patterns:
                if re.search(pattern, cname, re.I):
                    matched_pattern = True
                    break
            if not matched_pattern:
                continue

            # CNAME points to a takeover-prone service → check body fingerprint
            body = ""
            for scheme in ("https", "http"):
                try:
                    r = httpx.get(
                        f"{scheme}://{info.subdomain}",
                        headers=_HEADERS,
                        follow_redirects=True,
                        timeout=8,
                        verify=False,
                    )
                    body = r.text[:8000]
                    break
                except Exception:
                    pass

            for fp in body_fps:
                if fp.lower() in body.lower():
                    info.takeover_risk = True
                    info.takeover_service = service
                    break
            if info.takeover_risk:
                break

    def _check_takeovers(self):
        # Only probe subdomains with known service signatures in their hostname
        # or that have a CNAME (determined during probing)
        # Run concurrently — each call needs a DoH query
        candidates = list(self.subdomains.values())
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.probe_workers) as ex:
            futures = [
                ex.submit(self._check_takeover_single, info)
                for info in candidates
            ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # 7. Generate security findings
    # ------------------------------------------------------------------

    def _generate_findings(self):
        total = len(self.subdomains)
        active = [s for s in self.subdomains.values()
                  if s.status_code is not None]

        # --- Wildcard DNS ---
        if self.wildcard_detected:
            self.findings.append(Finding(
                title="Wildcard DNS détecté",
                severity="medium",
                category="A05 – Security Misconfiguration",
                description=(
                    f"Le domaine {self.domain} répond à tous les sous-domaines "
                    "inexistants (wildcard DNS). Cela masque la surface d'attaque "
                    "réelle et peut faciliter le phishing via des sous-domaines "
                    "homographiques."
                ),
                evidence=(
                    f"Résolution de sous-domaine aléatoire → "
                    f"{', '.join(self.wildcard_ips)}"
                ),
                remediation=(
                    "Supprimez l'entrée DNS wildcard (* IN A) sauf si elle est "
                    "strictement nécessaire. Si vous en avez besoin, limitez-la "
                    "à des enregistrements spécifiques."
                ),
                cvss_score=5.3,
            ))

        # --- Zone Transfer ---
        if self.zone_transfer_vuln:
            self.findings.append(Finding(
                title=(
                    f"Zone Transfer DNS (AXFR) activé — "
                    f"{len(self.zone_transfer_servers)} serveur(s)"
                ),
                severity="critical",
                category="A05 – Security Misconfiguration",
                description=(
                    "Un ou plusieurs serveurs DNS autorisent le transfert de zone "
                    "(AXFR) à n'importe quel client non authentifié. Cela révèle "
                    "la totalité de la zone DNS : tous les sous-domaines, IPs, "
                    "services internes et infrastructure cachée."
                ),
                evidence=f"AXFR accepté par : {', '.join(self.zone_transfer_servers)}",
                remediation=(
                    "Restreignez immédiatement les transferts de zone aux seuls "
                    "serveurs DNS secondaires légitimes (ACL par IP). Sur BIND : "
                    "allow-transfer { slave-ip; }; Sur PowerDNS : disable AXFR "
                    "pour les clients non autorisés."
                ),
                cvss_score=9.1,
            ))

        # --- Subdomain Takeovers ---
        takeover_list = [s for s in self.subdomains.values() if s.takeover_risk]
        for sub in takeover_list:
            self.findings.append(Finding(
                title=f"Subdomain Takeover : {sub.subdomain}",
                severity="critical",
                category="A01 – Broken Access Control",
                description=(
                    f"Le sous-domaine {sub.subdomain} pointe via CNAME vers "
                    f"{sub.cname} ({sub.takeover_service}), un service qui n'est "
                    "plus revendiqué. Un attaquant peut enregistrer ce service "
                    "gratuitement et prendre le contrôle total de ce sous-domaine "
                    "(vol de cookies, phishing, distribution de malware sous votre "
                    "domaine officiel)."
                ),
                evidence=(
                    f"CNAME: {sub.subdomain} → {sub.cname} | "
                    f"Service: {sub.takeover_service} | "
                    "Fingerprint de service non revendiqué détectée dans le body"
                ),
                remediation=(
                    f"Supprimez immédiatement l'enregistrement CNAME de "
                    f"{sub.subdomain}. Si le service {sub.takeover_service} "
                    "est toujours utilisé, revendiquez-le. Auditez tous vos "
                    "CNAMEs vers des services tiers."
                ),
                cvss_score=9.8,
            ))

        # --- Dev/Staging subdomains exposed ---
        dev_kws = ["dev.", "staging.", "stg.", "test.", "uat.",
                   "sandbox.", "preprod.", "pre.", "beta.", "alpha.", "demo."]
        dev_subs = [s for s in active
                    if any(s.subdomain.startswith(kw) or
                           f".{kw.rstrip('.')}" + "." in s.subdomain
                           for kw in dev_kws)
                    and s.status_code is not None
                    and s.status_code < 500]
        if dev_subs:
            names = [s.subdomain for s in dev_subs[:6]]
            tail = f" +{len(dev_subs)-6} autres" if len(dev_subs) > 6 else ""
            self.findings.append(Finding(
                title=f"{len(dev_subs)} environnement(s) de dev exposé(s) publiquement",
                severity="high",
                category="A05 – Security Misconfiguration",
                description=(
                    "Des sous-domaines d'environnements non-production (dev, "
                    "staging, test, sandbox) sont accessibles publiquement. "
                    "Ces environnements ont souvent des configurations moins "
                    "sécurisées, des credentials de test, des backdoors de "
                    "développeur, ou des données sensibles."
                ),
                evidence=f"Exposés : {', '.join(names)}{tail}",
                remediation=(
                    "Restreignez l'accès aux environnements de développement via "
                    "VPN ou whitelist IP. N'exposez jamais ces environnements "
                    "publiquement. Utilisez des variables d'environnement "
                    "distinctes de la production."
                ),
                cvss_score=7.5,
            ))

        # --- Admin panels exposed ---
        admin_kws = ["admin.", "panel.", "cpanel.", "control.", "manage.",
                     "console.", "phpmyadmin.", "adminer.", "dashboard."]
        admin_subs = [s for s in active
                      if any(s.subdomain.startswith(kw) for kw in admin_kws)
                      and s.status_code is not None
                      and s.status_code < 400]
        if admin_subs:
            names = [s.subdomain for s in admin_subs[:5]]
            tail = f" +{len(admin_subs)-5} autres" if len(admin_subs) > 5 else ""
            self.findings.append(Finding(
                title=f"{len(admin_subs)} interface(s) d'administration exposée(s)",
                severity="high",
                category="A01 – Broken Access Control",
                description=(
                    "Des interfaces d'administration sont directement accessibles "
                    "depuis Internet. Cela les expose à des attaques par force "
                    "brute, exploitation de CVEs non patchées, ou accès non "
                    "autorisé si l'authentification est faible."
                ),
                evidence=f"Interfaces exposées : {', '.join(names)}{tail}",
                remediation=(
                    "Limitez l'accès aux interfaces d'administration via VPN ou "
                    "whitelist IP. Activez l'authentification multi-facteurs (MFA). "
                    "Mettez en place un WAF avec détection de force brute."
                ),
                cvss_score=7.5,
            ))

        # --- Large attack surface ---
        if total > 30:
            sev = "high" if total > 100 else "medium"
            self.findings.append(Finding(
                title=f"Surface d'attaque étendue — {total} sous-domaines actifs",
                severity=sev,
                category="A05 – Security Misconfiguration",
                description=(
                    f"{total} sous-domaines actifs ont été découverts pour "
                    f"{self.domain}. Chaque sous-domaine est un point d'entrée "
                    "potentiel. Une grande surface d'attaque augmente les risques "
                    "de services non patchés, mal configurés ou oubliés."
                ),
                evidence=(
                    f"Total résolu : {total} | Actifs (HTTP) : {len(active)} | "
                    f"Sources : crt.sh ({self._sources['crtsh']}), "
                    f"hackertarget ({self._sources['hackertarget']}), "
                    f"brute-force ({self._sources['bruteforce']})"
                ),
                remediation=(
                    "Auditez régulièrement l'inventaire de vos sous-domaines. "
                    "Désactivez ou redirigez les sous-domaines inutilisés. "
                    "Mettez en place un processus de gestion du cycle de vie "
                    "des sous-domaines."
                ),
                cvss_score=6.5 if total > 100 else 4.0,
            ))

        # --- HTTP (non-HTTPS) services ---
        http_only = [s for s in active
                     if not s.https and s.status_code is not None
                     and s.status_code < 400]
        if http_only:
            names = [s.subdomain for s in http_only[:5]]
            tail = f" +{len(http_only)-5} autres" if len(http_only) > 5 else ""
            self.findings.append(Finding(
                title=f"{len(http_only)} sous-domaine(s) servent du contenu en HTTP non chiffré",
                severity="medium",
                category="A02 – Cryptographic Failures",
                description=(
                    f"{len(http_only)} sous-domaine(s) répondent en HTTP clair "
                    "sans redirection HTTPS. Le trafic est interceptable "
                    "(Man-in-the-Middle), les credentials et tokens sont "
                    "exposés sur le réseau."
                ),
                evidence=f"HTTP non chiffré : {', '.join(names)}{tail}",
                remediation=(
                    "Activez HTTPS sur tous vos sous-domaines. "
                    "Ajoutez des redirections 301 de HTTP vers HTTPS. "
                    "Configurez HSTS (Strict-Transport-Security) avec "
                    "includeSubDomains."
                ),
                cvss_score=5.3,
            ))

    # ------------------------------------------------------------------
    # 8. Build recon data dict
    # ------------------------------------------------------------------

    def _build_recon_data(self) -> Dict[str, Any]:
        active = [s for s in self.subdomains.values()
                  if s.status_code is not None]
        subdomain_list = [
            {
                "subdomain": s.subdomain,
                "ips": s.ips,
                "cname": s.cname,
                "status_code": s.status_code,
                "title": s.title,
                "server": s.server,
                "technologies": s.technologies,
                "https": s.https,
                "source": s.source,
                "takeover_risk": s.takeover_risk,
                "takeover_service": s.takeover_service,
            }
            for s in sorted(
                self.subdomains.values(),
                key=lambda s: (
                    0 if s.source in ("crt.sh", "hackertarget") else 1,
                    s.subdomain,
                ),
            )
        ]

        return {
            "domain": self.domain,
            "total_found": len(self.subdomains),
            "wildcard_detected": self.wildcard_detected,
            "wildcard_ips": list(self.wildcard_ips),
            "zone_transfer_vulnerable": self.zone_transfer_vuln,
            "zone_transfer_servers": self.zone_transfer_servers,
            "sources": self._sources,
            "subdomains": subdomain_list,
            "summary": {
                "total": len(self.subdomains),
                "active_http": len(active),
                "https_count": sum(1 for s in active if s.https),
                "http_only_count": sum(1 for s in active if not s.https),
                "takeover_risks": sum(
                    1 for s in self.subdomains.values() if s.takeover_risk),
                "dev_exposed": len([
                    s for s in active
                    if any(kw in s.subdomain
                           for kw in ["dev.", "staging.", "test.", "uat.",
                                      "sandbox.", "preprod.", "beta."])
                ]),
                "admin_exposed": len([
                    s for s in active
                    if any(s.subdomain.startswith(kw)
                           for kw in ["admin.", "panel.", "control.",
                                      "manage.", "console."])
                ]),
            },
        }
