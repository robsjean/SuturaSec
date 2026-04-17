"""
OSINT Recon Scanner — SuturaSec
Open-Source Intelligence gathering from free, passive sources:
  WHOIS · DNS records · SSL cert · IP geolocation · ASN/BGP
  Technology fingerprint · Email harvesting · Wayback Machine
  Breach data · GitHub exposure · Open ports
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


import httpx

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    cvss_score: float
    category: str
    evidence: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TECH_SIGNATURES: Dict[str, List[str]] = {
    "WordPress":   ["wp-content", "wp-includes", "wordpress"],
    "Drupal":      ["drupal", "sites/default/files"],
    "Joomla":      ["/components/com_", "joomla"],
    "Magento":     ["mage/", "varien/", "skin/frontend"],
    "Shopify":     ["cdn.shopify.com", "shopify"],
    "React":       ["__react", "data-reactroot", "react.production.min.js"],
    "Angular":     ["ng-version", "angular.min.js", "ng-app"],
    "Vue.js":      ["__vue__", "vue.min.js", "v-cloak"],
    "jQuery":      ["jquery.min.js", "jquery-"],
    "Bootstrap":   ["bootstrap.min.css", "bootstrap.bundle"],
    "Laravel":     ["laravel_session", "X-Powered-By: PHP"],
    "Django":      ["csrfmiddlewaretoken", "__django_debug"],
    "Ruby on Rails": ["X-Runtime", "_rails_session"],
    "ASP.NET":     ["asp.net", "__viewstate", "x-aspnet-version"],
    "Next.js":     ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js":     ["__nuxt", "_nuxt/"],
    "Spring":      ["X-Application-Context", "JSESSIONID"],
}

EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

OPEN_PORT_RISKS: Dict[int, Tuple[str, str, float]] = {
    21:    ("FTP",          "critical", 9.5),
    22:    ("SSH",          "medium",   5.0),
    23:    ("Telnet",       "critical", 9.8),
    25:    ("SMTP",         "medium",   5.5),
    3306:  ("MySQL",        "critical", 9.5),
    5432:  ("PostgreSQL",   "critical", 9.5),
    6379:  ("Redis",        "critical", 9.5),
    9200:  ("Elasticsearch","critical", 9.8),
    27017: ("MongoDB",      "critical", 9.5),
    5984:  ("CouchDB",      "high",     7.5),
    11211: ("Memcached",    "critical", 9.5),
    2375:  ("Docker API",   "critical", 10.0),
    2379:  ("etcd",         "critical", 9.5),
    9092:  ("Kafka",        "high",     7.5),
}


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class OSINTScanner:
    """Passive OSINT reconnaissance scanner."""

    def __init__(self, target: str):
        # Normalise: strip scheme and path, keep bare domain
        raw = target.strip()
        raw = re.sub(r'^https?://', '', raw)
        raw = re.sub(r'^www\.', '', raw)
        raw = raw.split('/')[0].split('?')[0].split(':')[0]
        self.domain = raw.lower()

        self.client = httpx.Client(
            timeout=httpx.Timeout(15.0),
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SuturaSec-OSINT/1.0)"},
        )

        self.findings: List[Finding] = []
        self._seen: set = set()

        # Data buckets
        self.ip_addresses: List[str] = []
        self.whois_data: Dict[str, Any] = {}
        self.dns_records: Dict[str, Any] = {}
        self.ssl_cert: Dict[str, Any] = {}
        self.asn_info: Dict[str, Any] = {}
        self.geo_info: Dict[str, Any] = {}
        self.technologies: Dict[str, Any] = {}
        self.emails_found: List[str] = []
        self.wayback: Dict[str, Any] = {}
        self.breach_data: Dict[str, Any] = {"breaches_found": 0, "breach_names": []}
        self.github_exposure: Dict[str, Any] = {"leaks_found": 0, "sample_repos": []}
        self.open_ports: List[int] = []
        self.dorks: List[str] = []

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> Tuple[List[Finding], Dict[str, Any]]:
        t0 = time.time()
        print(f"[OSINT] Starting recon on {self.domain}")

        # Resolve IPs first (needed by other checks)
        self._resolve_ips()

        # Parallel data gathering
        tasks = {
            "WHOIS":        self._gather_whois,
            "DNS":          self._gather_dns,
            "SSL":          self._gather_ssl,
            "GeoIP/ASN":    self._gather_geoip,
            "Technologies": self._gather_technologies,
            "Emails":       self._gather_emails,
            "Wayback":      self._gather_wayback,
            "Breaches":     self._gather_breaches,
            "GitHub":       self._gather_github,
            "Ports":        self._gather_ports,
        }
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(fn): name for name, fn in tasks.items()}
            for fut in as_completed(futs):
                name = futs[fut]
                try:
                    fut.result()
                    print(f"[OSINT] {name} done")
                except Exception as exc:
                    print(f"[OSINT] {name} error: {exc}")

        self._build_dorks()
        self._generate_findings()

        duration = round(time.time() - t0, 2)
        self.client.close()

        osint_results = {
            "domain": self.domain,
            "ip_addresses": self.ip_addresses,
            "asn_info": self.asn_info,
            "geo_info": self.geo_info,
            "whois": self.whois_data,
            "dns_records": self.dns_records,
            "ssl_cert": self.ssl_cert,
            "technologies": self.technologies,
            "emails_found": self.emails_found,
            "wayback": self.wayback,
            "breach_data": self.breach_data,
            "github_exposure": self.github_exposure,
            "open_ports": self.open_ports,
            "recommended_dorks": self.dorks,
            "scan_duration_seconds": duration,
            "sources_queried": list(tasks.keys()),
        }
        print(f"[OSINT] Done in {duration}s — {len(self.findings)} findings")
        return self.findings, osint_results

    # ------------------------------------------------------------------
    # IP resolution
    # ------------------------------------------------------------------

    def _resolve_ips(self):
        try:
            infos = socket.getaddrinfo(self.domain, None)
            self.ip_addresses = list({info[4][0] for info in infos})[:10]
            print(f"[OSINT] Resolved {self.domain} → {self.ip_addresses}")
        except Exception as e:
            print(f"[OSINT] DNS resolution failed: {e}")

    # ------------------------------------------------------------------
    # WHOIS
    # ------------------------------------------------------------------

    def _gather_whois(self):
        try:
            r = self.client.get(f"https://api.hackertarget.com/whois/?q={self.domain}")
            if r.status_code != 200:
                return
            text = r.text

            def extract(patterns, txt):
                for pat in patterns:
                    m = re.search(pat, txt, re.IGNORECASE | re.MULTILINE)
                    if m:
                        return m.group(1).strip()
                return ""

            registrar = extract([r'Registrar:\s*(.+)', r'registrar:\s*(.+)'], text)
            created   = extract([r'Creation Date:\s*(.+)', r'Created Date:\s*(.+)', r'created:\s*(.+)'], text)
            expires   = extract([r'Registry Expiry Date:\s*(.+)', r'Expiry Date:\s*(.+)', r'expires:\s*(.+)'], text)
            org       = extract([r'Registrant Organization:\s*(.+)', r'org:\s*(.+)'], text)
            ns_matches = re.findall(r'Name Server:\s*(.+)', text, re.IGNORECASE)

            self.whois_data = {
                "registrar": registrar,
                "created": created[:30] if created else "",
                "expires": expires[:30] if expires else "",
                "registrant_org": org,
                "nameservers": [ns.strip().lower() for ns in ns_matches[:6]],
                "raw_excerpt": text[:800],
            }

            # Check domain expiry
            if expires:
                try:
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
                        try:
                            exp_dt = datetime.strptime(expires[:20].strip(), fmt)
                            days_left = (exp_dt - datetime.utcnow()).days
                            self.whois_data["days_until_expiry"] = days_left
                            if days_left < 0:
                                self._add(Finding(
                                    title="Domain has expired",
                                    description=f"The domain `{self.domain}` expired {abs(days_left)} days ago.",
                                    severity="critical",
                                    cvss_score=9.8,
                                    category="OSINT - Domain Intelligence",
                                    evidence=f"Registry Expiry Date: {expires}",
                                    remediation="Renew the domain immediately to prevent domain squatting.",
                                ))
                            elif days_left <= 30:
                                self._add(Finding(
                                    title=f"Domain expiring soon ({days_left} days)",
                                    description=f"The domain `{self.domain}` expires in {days_left} days.",
                                    severity="high",
                                    cvss_score=7.5,
                                    category="OSINT - Domain Intelligence",
                                    evidence=f"Expiry: {expires}",
                                    remediation="Renew domain registration immediately.",
                                ))
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass

            # New domain check
            if created:
                try:
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
                        try:
                            cr_dt = datetime.strptime(created[:20].strip(), fmt)
                            age_days = (datetime.utcnow() - cr_dt).days
                            self.whois_data["domain_age_days"] = age_days
                            if age_days < 30:
                                self._add(Finding(
                                    title=f"Recently registered domain ({age_days} days old)",
                                    description=(
                                        f"The domain `{self.domain}` was registered only {age_days} days ago. "
                                        "Newly registered domains are commonly used in phishing, fraud, and malware campaigns."
                                    ),
                                    severity="medium",
                                    cvss_score=5.5,
                                    category="OSINT - Domain Intelligence",
                                    evidence=f"Creation Date: {created}",
                                    remediation="Verify this domain's legitimacy. If your own, ensure it is not impersonating a known brand.",
                                ))
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass
        except Exception as e:
            print(f"[OSINT] WHOIS error: {e}")

    # ------------------------------------------------------------------
    # DNS records
    # ------------------------------------------------------------------

    def _gather_dns(self):
        records: Dict[str, Any] = {
            "A": [], "AAAA": [], "MX": [], "NS": [],
            "TXT": [], "SOA": "", "CNAME": []
        }

        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
                try:
                    answers = resolver.resolve(self.domain, rtype)
                    if rtype == "MX":
                        records["MX"] = [f"{r.preference} {str(r.exchange)}" for r in answers]
                    elif rtype in ("NS", "CNAME"):
                        records[rtype] = [str(r) for r in answers]
                    elif rtype == "TXT":
                        records["TXT"] = [b''.join(r.strings).decode('utf-8', 'ignore') for r in answers]
                    else:
                        records[rtype] = [str(r) for r in answers]
                except Exception:
                    pass
            try:
                soa = resolver.resolve(self.domain, "SOA")
                records["SOA"] = str(soa[0])
            except Exception:
                pass
        else:
            # Fallback: HackerTarget DNS lookup
            try:
                r = self.client.get(f"https://api.hackertarget.com/dnslookup/?q={self.domain}")
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        parts = line.split()
                        if len(parts) >= 4:
                            rtype = parts[3].upper()
                            value = " ".join(parts[4:]) if len(parts) > 4 else ""
                            if rtype in records and isinstance(records[rtype], list):
                                records[rtype].append(value)
            except Exception:
                pass

        self.dns_records = records

        # Check SPF
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in t for t in txt_records)
        if not has_spf and records.get("MX"):
            self._add(Finding(
                title="SPF record missing",
                description=(
                    f"No SPF (Sender Policy Framework) TXT record found for `{self.domain}`. "
                    "Attackers can spoof emails appearing to originate from this domain."
                ),
                severity="medium",
                cvss_score=5.5,
                category="OSINT - DNS Misconfiguration",
                evidence=f"No TXT record starting with 'v=spf1' found for {self.domain}",
                remediation=(
                    "Add a TXT record: `v=spf1 include:your-mail-provider.com ~all`. "
                    "Use SPF policy testers to validate before publishing."
                ),
            ))

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            has_dmarc = False
            if HAS_DNSPYTHON:
                try:
                    answers = resolver.resolve(dmarc_domain, "TXT")
                    has_dmarc = any("v=DMARC1" in b''.join(r.strings).decode('utf-8', 'ignore')
                                    for r in answers)
                except Exception:
                    pass
            if not has_dmarc and records.get("MX"):
                self._add(Finding(
                    title="DMARC policy missing",
                    description=(
                        f"No DMARC record found at `_dmarc.{self.domain}`. "
                        "Without DMARC, email receivers cannot enforce SPF/DKIM alignment, "
                        "leaving the domain vulnerable to email spoofing and phishing."
                    ),
                    severity="medium",
                    cvss_score=5.5,
                    category="OSINT - DNS Misconfiguration",
                    evidence=f"No DMARC TXT record at _dmarc.{self.domain}",
                    remediation=(
                        "Add a TXT record at `_dmarc.{domain}`: "
                        "`v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`"
                    ),
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SSL certificate
    # ------------------------------------------------------------------

    def _gather_ssl(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            if not cert:
                self.ssl_cert = {"available": False}
                return

            subject_dict = dict(x[0] for x in cert.get("subject", []))
            issuer_dict  = dict(x[0] for x in cert.get("issuer", []))
            not_after_str = cert.get("notAfter", "")
            not_before_str = cert.get("notBefore", "")

            # Parse expiry
            days_remaining = None
            try:
                exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (exp_dt - datetime.utcnow()).days
            except Exception:
                pass

            # SANs
            sans = []
            for typ, val in cert.get("subjectAltName", []):
                if typ == "DNS":
                    sans.append(val)

            # Self-signed check
            is_self_signed = subject_dict.get("commonName") == issuer_dict.get("organizationName")
            cn = subject_dict.get("commonName", "")

            self.ssl_cert = {
                "subject": cn,
                "issuer": issuer_dict.get("organizationName", ""),
                "not_before": not_before_str,
                "not_after": not_after_str,
                "days_remaining": days_remaining,
                "sans": sans[:20],
                "cipher": cipher[0] if cipher else "",
                "is_self_signed": is_self_signed,
            }

            # Findings
            if days_remaining is not None:
                if days_remaining <= 0:
                    self._add(Finding(
                        title="SSL certificate has expired",
                        description=f"The TLS certificate for `{self.domain}` expired {abs(days_remaining)} days ago.",
                        severity="critical",
                        cvss_score=9.5,
                        category="OSINT - SSL/TLS Issue",
                        evidence=f"Not After: {not_after_str}",
                        remediation="Renew the certificate immediately. Consider auto-renewal with Let's Encrypt/Certbot.",
                    ))
                elif days_remaining <= 7:
                    self._add(Finding(
                        title=f"SSL certificate expires in {days_remaining} days",
                        description="Certificate renewal is critically overdue.",
                        severity="critical",
                        cvss_score=9.5,
                        category="OSINT - SSL/TLS Issue",
                        evidence=f"Not After: {not_after_str}",
                        remediation="Renew the certificate immediately.",
                    ))
                elif days_remaining <= 30:
                    self._add(Finding(
                        title=f"SSL certificate expires soon ({days_remaining} days)",
                        description="The TLS certificate will expire soon, causing browser warnings and service disruption.",
                        severity="high",
                        cvss_score=7.5,
                        category="OSINT - SSL/TLS Issue",
                        evidence=f"Not After: {not_after_str}",
                        remediation="Renew the certificate now.",
                    ))

            if is_self_signed:
                self._add(Finding(
                    title="Self-signed SSL certificate detected",
                    description=(
                        f"The certificate for `{self.domain}` is self-signed. "
                        "Browsers will display security warnings, and the certificate "
                        "provides no third-party identity assurance."
                    ),
                    severity="high",
                    cvss_score=7.0,
                    category="OSINT - SSL/TLS Issue",
                    evidence=f"Subject CN: {cn} | Issuer: {issuer_dict.get('organizationName', '')}",
                    remediation="Replace self-signed certificate with one from a trusted CA (e.g., Let's Encrypt).",
                ))

            # CN mismatch
            if cn and self.domain not in cn and f"*.{'.'.join(self.domain.split('.')[1:])}" not in cn:
                if cn not in sans:
                    self._add(Finding(
                        title="SSL certificate domain mismatch",
                        description=(
                            f"The certificate CN `{cn}` does not match the target domain `{self.domain}`. "
                            "This causes browser SSL errors and may indicate misconfiguration."
                        ),
                        severity="high",
                        cvss_score=7.0,
                        category="OSINT - SSL/TLS Issue",
                        evidence=f"Cert CN: {cn} | Target: {self.domain} | SANs: {', '.join(sans[:5])}",
                        remediation="Obtain a certificate that covers the correct domain name.",
                    ))

        except Exception as e:
            self.ssl_cert = {"available": False, "error": str(e)[:100]}

    # ------------------------------------------------------------------
    # GeoIP / ASN
    # ------------------------------------------------------------------

    def _gather_geoip(self):
        ip = self.ip_addresses[0] if self.ip_addresses else None
        if not ip:
            return
        try:
            r = self.client.get(f"https://api.hackertarget.com/geoip/?q={ip}")
            if r.status_code == 200:
                geo: Dict[str, str] = {}
                for line in r.text.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        geo[k.strip().lower().replace(" ", "_")] = v.strip()
                self.geo_info = geo
        except Exception:
            pass

        try:
            r2 = self.client.get(f"https://api.bgpview.io/ip/{ip}",
                                  headers={"Accept": "application/json"})
            if r2.status_code == 200:
                data = r2.json().get("data", {})
                prefixes = data.get("prefixes", [])
                if prefixes:
                    p = prefixes[0]
                    asn = p.get("asn", {})
                    self.asn_info = {
                        "asn": f"AS{asn.get('asn', '')}",
                        "org": asn.get("description", ""),
                        "country": asn.get("country_code", ""),
                        "prefix": p.get("prefix", ""),
                    }
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    def _gather_technologies(self):
        try:
            r = self.client.get(f"https://{self.domain}")
            headers = {k.lower(): v for k, v in r.headers.items()}
            html = r.text[:50000]

            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")
            generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
            generator = generator_match.group(1) if generator_match else ""

            detected_frameworks = []
            for fw, sigs in TECH_SIGNATURES.items():
                if any(sig.lower() in html.lower() or sig.lower() in str(headers).lower()
                       for sig in sigs):
                    detected_frameworks.append(fw)

            cms = generator or next((fw for fw in detected_frameworks
                                     if fw in ("WordPress", "Drupal", "Joomla", "Magento", "Shopify")), "")

            self.technologies = {
                "server": server,
                "powered_by": powered_by,
                "generator": generator,
                "cms": cms,
                "frameworks": detected_frameworks,
            }

            # Findings
            if re.search(r'\d+\.\d+', server):
                self._add(Finding(
                    title="Server version disclosed in HTTP headers",
                    description=f"The `Server` header reveals version info: `{server}`. Attackers can target known CVEs.",
                    severity="low",
                    cvss_score=3.0,
                    category="OSINT - Infrastructure Exposure",
                    evidence=f"Server: {server}",
                    remediation="Configure your web server to suppress version information from headers.",
                ))
            if powered_by:
                self._add(Finding(
                    title="X-Powered-By header discloses technology stack",
                    description=f"The `X-Powered-By` header reveals: `{powered_by}`. This aids attacker reconnaissance.",
                    severity="low",
                    cvss_score=2.5,
                    category="OSINT - Infrastructure Exposure",
                    evidence=f"X-Powered-By: {powered_by}",
                    remediation="Remove the `X-Powered-By` header from all responses.",
                ))
        except Exception as e:
            print(f"[OSINT] Tech fingerprint error: {e}")

    # ------------------------------------------------------------------
    # Email harvesting
    # ------------------------------------------------------------------

    def _gather_emails(self):
        emails: set = set()
        domain_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@' + re.escape(self.domain) + r'\b', re.I
        )

        # Scrape main pages
        for url in [f"https://{self.domain}", f"https://{self.domain}/contact",
                    f"https://{self.domain}/about", f"https://www.{self.domain}"]:
            try:
                r = self.client.get(url)
                found = domain_pattern.findall(r.text)
                emails.update(e.lower() for e in found)
            except Exception:
                pass

        # HackerTarget pagelinks
        try:
            r = self.client.get(f"https://api.hackertarget.com/pagelinks/?q=https://{self.domain}")
            if r.status_code == 200:
                found = domain_pattern.findall(r.text)
                emails.update(e.lower() for e in found)
        except Exception:
            pass

        self.emails_found = sorted(emails)[:20]

        if len(self.emails_found) > 5:
            self._add(Finding(
                title=f"Large number of corporate email addresses exposed ({len(self.emails_found)})",
                description=(
                    f"{len(self.emails_found)} email addresses were harvested from public pages "
                    f"of `{self.domain}`. This enables targeted phishing, spear-phishing, "
                    "and credential stuffing attacks."
                ),
                severity="medium",
                cvss_score=5.5,
                category="OSINT - Email Exposure",
                evidence="Emails: " + ", ".join(self.emails_found[:5]) + ("..." if len(self.emails_found) > 5 else ""),
                remediation=(
                    "Use contact forms instead of mailto links. "
                    "Obfuscate email addresses on public pages with JavaScript. "
                    "Enroll exposed addresses in breach monitoring."
                ),
            ))
        elif self.emails_found:
            self._add(Finding(
                title=f"Corporate email addresses found on public pages ({len(self.emails_found)})",
                description=f"Email addresses for `{self.domain}` are visible on public web pages.",
                severity="low",
                cvss_score=3.0,
                category="OSINT - Email Exposure",
                evidence="Emails: " + ", ".join(self.emails_found),
                remediation="Consider obfuscating email addresses to reduce harvesting exposure.",
            ))

    # ------------------------------------------------------------------
    # Wayback Machine
    # ------------------------------------------------------------------

    def _gather_wayback(self):
        try:
            r = self.client.get(f"https://archive.org/wayback/available?url={self.domain}")
            if r.status_code == 200:
                data = r.json()
                snap = data.get("archived_snapshots", {}).get("closest", {})
                available = snap.get("available", False)
                ts = snap.get("timestamp", "")
                self.wayback = {
                    "available": available,
                    "closest_snapshot": snap.get("url", ""),
                    "closest_timestamp": ts,
                }
        except Exception:
            self.wayback = {"available": False}

        # CDX API for oldest snapshot
        try:
            r2 = self.client.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={self.domain}&output=json&limit=1&fl=timestamp&from=19960101&fastLatest=false&collapse=timestamp:4"
            )
            if r2.status_code == 200:
                rows = r2.json()
                if len(rows) > 1:
                    self.wayback["oldest_snapshot"] = rows[1][0] if rows[1] else ""
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Breach data
    # ------------------------------------------------------------------

    def _gather_breaches(self):
        try:
            r = self.client.get(
                f"https://api.xposedornot.com/v1/domain-summary/domain_summary?domain={self.domain}",
                headers={"Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json()
                breaches = data.get("BreachesSummary", {})
                breach_list = breaches.get("site", [])
                if isinstance(breach_list, str):
                    breach_list = [breach_list] if breach_list else []
                count = len(breach_list)
                self.breach_data = {
                    "breaches_found": count,
                    "breach_names": breach_list[:10],
                }
                if count > 0:
                    self._add(Finding(
                        title=f"Domain found in {count} data breach(es)",
                        description=(
                            f"Credentials or data associated with `{self.domain}` were found in "
                            f"{count} publicly known data breach(es). Affected accounts may be "
                            "targeted via credential stuffing attacks."
                        ),
                        severity="critical",
                        cvss_score=9.0,
                        category="OSINT - Data Breach",
                        evidence="Breaches: " + ", ".join(breach_list[:5]),
                        remediation=(
                            "Force password resets for all affected users. "
                            "Enable MFA. Monitor for credential stuffing patterns. "
                            "Notify affected users as required by GDPR/CCPA."
                        ),
                    ))
        except Exception as e:
            print(f"[OSINT] Breach check error: {e}")

    # ------------------------------------------------------------------
    # GitHub exposure
    # ------------------------------------------------------------------

    def _gather_github(self):
        leaks = 0
        repos: set = set()
        queries = [
            f"{self.domain}+password+in:file",
            f"{self.domain}+api_key+in:file",
            f"{self.domain}+secret+in:file",
        ]
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SuturaSec-OSINT/1.0",
        }
        for q in queries:
            try:
                r = self.client.get(
                    f"https://api.github.com/search/code?q={q}&per_page=5",
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    count = data.get("total_count", 0)
                    leaks += count
                    for item in data.get("items", []):
                        repo = item.get("repository", {}).get("full_name", "")
                        if repo:
                            repos.add(repo)
                elif r.status_code == 403:
                    break  # Rate limited
            except Exception:
                pass

        self.github_exposure = {
            "leaks_found": leaks,
            "sample_repos": list(repos)[:5],
        }

        if leaks > 0:
            self._add(Finding(
                title=f"Domain credentials/secrets potentially exposed on GitHub ({leaks} results)",
                description=(
                    f"GitHub code search found ~{leaks} file(s) containing `{self.domain}` "
                    "alongside keywords like `password`, `api_key`, or `secret`. "
                    "This may indicate hardcoded credentials or secrets in public repositories."
                ),
                severity="critical",
                cvss_score=9.2,
                category="OSINT - Code Repository Exposure",
                evidence=f"GitHub search results: {leaks} | Repos: {', '.join(list(repos)[:3])}",
                remediation=(
                    "Search GitHub for your domain and revoke any exposed secrets immediately. "
                    "Use git-secrets or truffleHog for pre-commit scanning. "
                    "Rotate all credentials found in public repositories."
                ),
            ))

    # ------------------------------------------------------------------
    # Open ports
    # ------------------------------------------------------------------

    def _gather_ports(self):
        ip = self.ip_addresses[0] if self.ip_addresses else None
        if not ip:
            return

        # Try HackerTarget nmap (free tier)
        try:
            r = self.client.get(f"https://api.hackertarget.com/nmap/?q={ip}",
                                 timeout=httpx.Timeout(30.0))
            if r.status_code == 200 and "open" in r.text.lower():
                for line in r.text.splitlines():
                    m = re.search(r'(\d+)/tcp\s+open', line)
                    if m:
                        port = int(m.group(1))
                        self.open_ports.append(port)
        except Exception:
            pass

        # Quick TCP connect probe for highest-risk ports
        risky = [3306, 5432, 6379, 9200, 27017, 5984, 11211, 2375, 2379]
        for port in risky:
            if port in self.open_ports:
                continue
            try:
                with socket.create_connection((ip, port), timeout=2):
                    self.open_ports.append(port)
            except Exception:
                pass

        self.open_ports = sorted(set(self.open_ports))

        # Findings for risky open ports
        for port in self.open_ports:
            if port in OPEN_PORT_RISKS:
                service, sev, score = OPEN_PORT_RISKS[port]
                self._add(Finding(
                    title=f"Exposed {service} port ({port}) publicly accessible",
                    description=(
                        f"Port {port} ({service}) is open and reachable from the internet on `{ip}`. "
                        f"Publicly exposed {service} instances are a prime target for data theft, "
                        "ransomware, and cryptomining attacks."
                    ),
                    severity=sev,
                    cvss_score=score,
                    category="OSINT - Open Port Exposure",
                    evidence=f"{ip}:{port} ({service}) — TCP connection accepted",
                    remediation=(
                        f"Restrict {service} access to internal networks or VPN. "
                        "Use firewall rules (iptables/security groups) to block public access. "
                        "Enable authentication and encryption if external access is required."
                    ),
                ))

    # ------------------------------------------------------------------
    # Recommended Google dorks
    # ------------------------------------------------------------------

    def _build_dorks(self):
        d = self.domain
        self.dorks = [
            f'site:{d} filetype:pdf',
            f'site:{d} filetype:xls OR filetype:xlsx OR filetype:csv',
            f'site:{d} filetype:sql OR filetype:bak OR filetype:log',
            f'site:{d} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:panel',
            f'site:{d} inurl:api OR inurl:swagger OR inurl:graphql',
            f'site:{d} "error" OR "exception" OR "stack trace" OR "debug"',
            f'site:{d} "DB_PASSWORD" OR "API_KEY" OR "SECRET_KEY"',
            f'"{d}" site:pastebin.com OR site:paste.ee OR site:hastebin.com',
            f'"{d}" password OR secret OR credential site:github.com',
            f'"{d}" site:shodan.io',
            f'"{d}" "@{d}" email filetype:txt',
            f'site:{d} ext:env OR ext:config OR ext:conf',
        ]

    # ------------------------------------------------------------------
    # Generate findings from gathered data
    # ------------------------------------------------------------------

    def _generate_findings(self):
        # Findings are generated inline during gathering.
        # This method handles any cross-source findings.

        # No HTTPS at all
        if not self.ssl_cert.get("subject") and not self.ssl_cert.get("error"):
            # Could not connect on 443 — check if site responds on HTTP
            try:
                r = self.client.get(f"http://{self.domain}", timeout=httpx.Timeout(8.0))
                if r.status_code < 500:
                    self._add(Finding(
                        title="Website served over HTTP without HTTPS",
                        description=(
                            f"The domain `{self.domain}` does not appear to support HTTPS. "
                            "All traffic is transmitted in cleartext."
                        ),
                        severity="high",
                        cvss_score=7.4,
                        category="OSINT - SSL/TLS Issue",
                        evidence=f"HTTP GET https://{self.domain} failed; HTTP accessible",
                        remediation="Enable HTTPS with a valid TLS certificate. Use Let's Encrypt for free certificates.",
                    ))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _add(self, finding: Finding):
        key = (finding.title[:60], finding.severity)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding)
