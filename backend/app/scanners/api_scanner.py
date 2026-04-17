"""
API Security Scanner — OWASP API Top 10 (2023)
Discovers endpoints and audits them for common API vulnerabilities.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx


# ---------------------------------------------------------------------------
# Finding dataclass (mirrors the one used across other scanners)
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

SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs",
    "/docs/swagger.json", "/docs/openapi.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/swagger-ui.html", "/swagger-ui",
    "/redoc",
]

COMMON_API_PATHS = [
    # Versioned bases
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    # Auth
    "/api/v1/auth", "/api/auth", "/auth",
    "/api/v1/login", "/api/login", "/login",
    "/api/v1/logout", "/api/logout",
    "/api/v1/register", "/api/register", "/register",
    "/api/v1/token", "/api/token", "/token",
    "/api/v1/refresh", "/api/refresh",
    "/api/v1/oauth", "/api/oauth", "/oauth",
    "/api/v1/forgot-password", "/api/forgot-password",
    "/api/v1/reset-password",
    # Users
    "/api/v1/users", "/api/users", "/users",
    "/api/v1/user", "/api/user", "/user",
    "/api/v1/users/me", "/api/users/me",
    "/api/v1/profile", "/api/profile", "/profile",
    "/api/v1/account", "/api/account",
    # Admin
    "/api/v1/admin", "/api/admin", "/admin",
    "/api/v1/admin/users",
    "/api/v1/config", "/api/config", "/config",
    "/api/v1/settings", "/api/settings", "/settings",
    "/api/v1/dashboard",
    # Data
    "/api/v1/products", "/api/products",
    "/api/v1/orders", "/api/orders",
    "/api/v1/payments", "/api/payments",
    "/api/v1/invoices",
    "/api/v1/files", "/api/files", "/files",
    "/api/v1/upload", "/api/upload", "/upload",
    "/api/v1/export", "/api/export", "/export",
    "/api/v1/data", "/api/data",
    "/api/v1/reports",
    # Health / debug / observability
    "/health", "/api/health", "/healthz", "/ready",
    "/status", "/api/status",
    "/ping", "/api/ping",
    "/metrics", "/api/metrics",
    "/debug", "/api/debug",
    "/info", "/api/info",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/info", "/actuator/metrics",
    "/actuator/logfile", "/actuator/heapdump",
    # GraphQL
    "/graphql", "/api/graphql", "/gql",
    # Other
    "/api/v1/search", "/search",
    "/api/v1/webhooks", "/webhooks",
]

SENSITIVE_PATH_KEYWORDS = {
    "admin", "config", "settings", "users", "user", "account",
    "export", "data", "payment", "invoice", "secret", "credential",
    "password", "key", "token", "private",
}

SENSITIVE_DATA_PATTERNS = [
    re.compile(r'(?i)"?password"?\s*:\s*"[^"]{3,}"'),
    re.compile(r'(?i)"?secret"?\s*:\s*"[^"]{3,}"'),
    re.compile(r'(?i)"?api_?key"?\s*:\s*"[^"]{3,}"'),
    re.compile(r'(?i)"?access_?token"?\s*:\s*"[^"]{3,}"'),
    re.compile(r'(?i)"?private_?key"?\s*:\s*"[^"]{3,}"'),
    re.compile(r'(?i)"?auth_?token"?\s*:\s*"[^"]{3,}"'),
    re.compile(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    re.compile(r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'),
    re.compile(r'192\.168\.\d{1,3}\.\d{1,3}'),
]

ERROR_PATTERNS = [
    re.compile(r'(?i)(stack\s*trace|traceback|at\s+\w+\.\w+\([\w.]+:\d+\))'),
    re.compile(r'(?i)(sqlexception|sql\s+error|mysql_error|pg_query|ORA-\d{5})'),
    re.compile(r'(?i)(django|flask|rails|laravel|spring\s+boot|express\.js)\s+(debug|error|exception)'),
    re.compile(r'(?i)(<b>Warning</b>:|<b>Fatal error</b>:|<b>Parse error</b>:)'),
    re.compile(r'(?i)(Whitelabel\s+Error\s+Page|There was an unexpected error)'),
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name kind}}}"}'
MAX_ENDPOINTS = 80


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class APIScanner:
    """OWASP API Top 10 (2023) scanner."""

    def __init__(self, target: str):
        raw = target.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        self.base_url = raw.rstrip("/")
        parsed = urlparse(self.base_url)
        self.scheme = parsed.scheme

        self.client = httpx.Client(
            timeout=httpx.Timeout(10.0),
            verify=False,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SuturaSec-APIScanner/1.0)",
                "Accept": "application/json, */*",
            },
        )

        self.findings: List[Finding] = []
        self.endpoints_found: List[Dict[str, Any]] = []
        self.swagger_url: Optional[str] = None
        self.graphql_found: bool = False
        self._seen: set = set()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> Tuple[List[Finding], Dict[str, Any]]:
        t0 = time.time()
        print(f"[APIScanner] Starting scan on {self.base_url}")

        self._check_ssl()
        self._discover_endpoints()
        print(f"[APIScanner] Found {len(self.endpoints_found)} endpoints")

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(self._audit_endpoint, ep) for ep in self.endpoints_found]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as exc:
                    print(f"[APIScanner] Audit error: {exc}")

        self._check_cors_global()
        self._check_rate_limiting()
        self._check_graphql()
        self._check_security_headers()
        self._check_http_methods()

        duration = round(time.time() - t0, 2)
        self.client.close()

        api_results = {
            "total_endpoints": len(self.endpoints_found),
            "endpoints_found": [
                {k: v for k, v in ep.items() if not k.startswith("_")}
                for ep in self.endpoints_found
            ],
            "swagger_found": self.swagger_url is not None,
            "swagger_url": self.swagger_url,
            "graphql_found": self.graphql_found,
            "checks_performed": len(self.endpoints_found) * 5,
            "owasp_coverage": list({f.category for f in self.findings}),
            "base_url": self.base_url,
            "scan_duration_seconds": duration,
        }
        print(f"[APIScanner] Done in {duration}s — {len(self.findings)} findings")
        return self.findings, api_results

    # ------------------------------------------------------------------
    # SSL check
    # ------------------------------------------------------------------

    def _check_ssl(self):
        if self.scheme == "http":
            self._add(Finding(
                title="API served over unencrypted HTTP",
                description=(
                    f"The API at {self.base_url} is served over plain HTTP. "
                    "All traffic including authentication tokens and sensitive data "
                    "is transmitted in cleartext and can be intercepted by network attackers."
                ),
                severity="high",
                cvss_score=7.4,
                category="API8:2023 - Security Misconfiguration",
                evidence=f"Target URL scheme: {self.scheme}",
                remediation=(
                    "Enforce HTTPS for all API endpoints. Obtain a valid TLS certificate "
                    "and redirect all HTTP traffic to HTTPS. Enable HSTS."
                ),
            ))

    # ------------------------------------------------------------------
    # Endpoint discovery
    # ------------------------------------------------------------------

    def _probe(self, path: str) -> Optional[Dict[str, Any]]:
        url = self.base_url + path
        try:
            t0 = time.time()
            r = self.client.get(url)
            if r.status_code in (404, 410):
                return None
            return {
                "path": path,
                "method": "GET",
                "status_code": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "response_time_ms": int((time.time() - t0) * 1000),
                "response_size": len(r.content),
                "url": url,
                "_body": r.text[:3000],
                "_headers": dict(r.headers),
            }
        except Exception:
            return None

    def _discover_endpoints(self):
        # 1. Spec files first
        for path in SPEC_PATHS:
            result = self._probe(path)
            if result and result["status_code"] < 400:
                self.endpoints_found.append(result)
                ct = result.get("content_type", "")
                if ("json" in ct or "yaml" in ct or "text/plain" in ct) and self.swagger_url is None:
                    self.swagger_url = result["url"]
                    self._parse_swagger(result["_body"])

        # 2. Common paths in parallel
        existing = {ep["path"] for ep in self.endpoints_found}
        to_check = [p for p in COMMON_API_PATHS if p not in existing]

        with ThreadPoolExecutor(max_workers=15) as pool:
            futs = {pool.submit(self._probe, p): p for p in to_check}
            for fut in as_completed(futs):
                result = fut.result()
                if result and result["status_code"] not in (404, 410, 400):
                    self.endpoints_found.append(result)

        # Deduplicate and cap
        seen_paths: set = set()
        unique = []
        for ep in self.endpoints_found:
            if ep["path"] not in seen_paths:
                seen_paths.add(ep["path"])
                unique.append(ep)
        self.endpoints_found = unique[:MAX_ENDPOINTS]

    def _parse_swagger(self, body: str):
        try:
            import json
            spec = json.loads(body)
            base = spec.get("basePath", "")
            for path in list(spec.get("paths", {}).keys())[:30]:
                clean = re.sub(r'\{[^}]+\}', '1', path)
                full = (base + clean).lstrip("/")
                full = "/" + full
                if full not in {ep["path"] for ep in self.endpoints_found}:
                    r = self._probe(full)
                    if r:
                        self.endpoints_found.append(r)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Per-endpoint audit
    # ------------------------------------------------------------------

    def _audit_endpoint(self, ep: Dict[str, Any]):
        self._check_unauth_access(ep)
        self._check_sensitive_data(ep["path"], ep.get("_body", ""))
        self._check_error_disclosure(ep["path"], ep.get("_body", ""), ep.get("_headers", {}))
        self._check_debug_endpoints(ep)

    def _check_unauth_access(self, ep: Dict[str, Any]):
        path = ep["path"]
        status = ep["status_code"]
        if not any(kw in path.lower() for kw in SENSITIVE_PATH_KEYWORDS):
            return
        if status in (200, 201, 206):
            is_admin = any(kw in path.lower() for kw in ("admin", "config"))
            self._add(Finding(
                title=f"Unauthenticated access to sensitive endpoint: {path}",
                description=(
                    f"The endpoint `{path}` returned HTTP {status} without any "
                    "authentication headers. Sensitive resources must require credentials."
                ),
                severity="critical" if is_admin else "high",
                cvss_score=9.1 if is_admin else 7.5,
                category="API2:2023 - Broken Authentication",
                evidence=f"GET {self.base_url}{path} → HTTP {status} (no auth headers sent)",
                remediation=(
                    "Enforce authentication (JWT Bearer, OAuth2, API key) on all non-public endpoints. "
                    "Return HTTP 401 for unauthenticated requests."
                ),
            ))

    def _check_sensitive_data(self, path: str, body: str):
        matches = [m.group(0)[:80] for pat in SENSITIVE_DATA_PATTERNS if (m := pat.search(body))]
        if matches:
            self._add(Finding(
                title=f"Sensitive data exposed in response: {path}",
                description=(
                    f"The response from `{path}` contains sensitive field values such as "
                    "passwords, tokens, API keys, or internal IP addresses."
                ),
                severity="high",
                cvss_score=7.5,
                category="API3:2023 - Broken Object Property Level Authorization",
                evidence="Matched: " + "; ".join(matches[:3]),
                remediation=(
                    "Use allowlist serializers — explicitly list fields to return. "
                    "Never include secrets, hashed passwords, or internal details in API responses."
                ),
            ))

    def _check_error_disclosure(self, path: str, body: str, headers: Dict):
        for pat in ERROR_PATTERNS:
            m = pat.search(body)
            if m:
                self._add(Finding(
                    title=f"Verbose error / stack trace disclosed: {path}",
                    description=(
                        f"The response from `{path}` contains a stack trace or detailed error "
                        "message that reveals internal framework, file paths, or database info."
                    ),
                    severity="high",
                    cvss_score=7.5,
                    category="API8:2023 - Security Misconfiguration",
                    evidence=m.group(0)[:200],
                    remediation="Disable debug mode in production. Return generic error messages to clients.",
                ))
                break

        server = headers.get("server", "") or headers.get("x-powered-by", "")
        if re.search(r'\d+\.\d+', server):
            self._add(Finding(
                title="Server version disclosed in headers",
                description=(
                    f"Response headers reveal the server software version: `{server}`. "
                    "Attackers use this to target known CVEs for that exact version."
                ),
                severity="medium",
                cvss_score=5.3,
                category="API8:2023 - Security Misconfiguration",
                evidence=f"Server/X-Powered-By: {server} (from {path})",
                remediation="Remove version info from Server and X-Powered-By headers.",
            ))

    def _check_debug_endpoints(self, ep: Dict[str, Any]):
        path = ep["path"]
        status = ep["status_code"]
        body = ep.get("_body", "")
        pl = path.lower()

        actuator_dangerous = ["/actuator/env", "/actuator/beans", "/actuator/mappings",
                              "/actuator/heapdump", "/actuator/logfile"]
        if any(pl.endswith(d) for d in actuator_dangerous) and status == 200:
            self._add(Finding(
                title=f"Spring Boot Actuator sensitive endpoint exposed: {path}",
                description=(
                    f"The Spring Boot Actuator endpoint `{path}` is publicly accessible "
                    "and can leak environment variables, secrets, bean definitions, or heap dumps."
                ),
                severity="critical",
                cvss_score=9.8,
                category="API9:2023 - Improper Inventory Management",
                evidence=f"GET {self.base_url}{path} → HTTP {status}",
                remediation=(
                    "Restrict Actuator endpoints: `management.endpoints.web.exposure.include=health,info`. "
                    "Secure with Spring Security and IP allowlisting."
                ),
            ))
        elif "/debug" in pl and status == 200:
            self._add(Finding(
                title=f"Debug endpoint publicly accessible: {path}",
                description=f"A debug endpoint `{path}` is accessible without authentication.",
                severity="high",
                cvss_score=8.1,
                category="API9:2023 - Improper Inventory Management",
                evidence=f"GET {self.base_url}{path} → HTTP {status}",
                remediation="Remove debug endpoints from production or restrict to internal networks.",
            ))
        elif "/metrics" in pl and status == 200 and len(body) > 200:
            self._add(Finding(
                title=f"Metrics endpoint publicly accessible: {path}",
                description="Application metrics are publicly accessible, revealing internal service topology.",
                severity="medium",
                cvss_score=5.3,
                category="API9:2023 - Improper Inventory Management",
                evidence=f"GET {self.base_url}{path} → HTTP {status}, {len(body)} bytes",
                remediation="Restrict metrics to internal networks or authenticated users.",
            ))

    # ------------------------------------------------------------------
    # Global targeted checks
    # ------------------------------------------------------------------

    def _check_cors_global(self):
        evil = "https://evil-attacker.com"
        test_paths = ["/api", "/api/v1", "/"] + [ep["path"] for ep in self.endpoints_found[:2]]
        for path in test_paths[:4]:
            try:
                r = self.client.get(self.base_url + path, headers={"Origin": evil})
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "false").lower()
                if (acao == "*" or acao == evil) and acac == "true":
                    self._add(Finding(
                        title="Critical CORS misconfiguration — credentials from any origin",
                        description=(
                            "The API reflects arbitrary Origin headers and sets "
                            "`Access-Control-Allow-Credentials: true`. Attackers can make "
                            "authenticated cross-origin requests on behalf of logged-in victims."
                        ),
                        severity="critical",
                        cvss_score=9.0,
                        category="API8:2023 - Security Misconfiguration",
                        evidence=(
                            f"Origin: {evil} → ACAO: {acao}, ACAC: {acac}"
                        ),
                        remediation=(
                            "Never combine `Access-Control-Allow-Origin: *` with "
                            "`Access-Control-Allow-Credentials: true`. "
                            "Use an explicit origin allowlist."
                        ),
                    ))
                    return
                elif acao == "*":
                    self._add(Finding(
                        title="CORS wildcard origin configured",
                        description="The API responds to any origin with `Access-Control-Allow-Origin: *`.",
                        severity="low",
                        cvss_score=3.5,
                        category="API8:2023 - Security Misconfiguration",
                        evidence=f"ACAO: * on {path}",
                        remediation="Replace wildcard with an explicit list of trusted origins.",
                    ))
                    return
            except Exception:
                continue

    def _check_rate_limiting(self):
        auth_paths = ["/api/v1/login", "/api/login", "/login",
                      "/api/v1/auth", "/api/auth", "/api/v1/token"]
        target_path = next(
            (p for p in auth_paths if any(ep["path"] == p for ep in self.endpoints_found)),
            auth_paths[0]
        )
        url = self.base_url + target_path
        payload = b'{"username":"test@test.com","password":"wrongpassword"}'
        got_429 = False
        try:
            for _ in range(15):
                r = self.client.post(url, content=payload,
                                     headers={"Content-Type": "application/json"})
                if r.status_code == 429:
                    got_429 = True
                    break
        except Exception:
            return
        if not got_429:
            self._add(Finding(
                title="No rate limiting on authentication endpoint",
                description=(
                    f"15 consecutive authentication requests to `{target_path}` were accepted "
                    "without HTTP 429. Brute-force and credential stuffing attacks are possible."
                ),
                severity="high",
                cvss_score=7.5,
                category="API4:2023 - Unrestricted Resource Consumption",
                evidence=f"15 POST requests to {target_path} — no 429 received",
                remediation=(
                    "Implement rate limiting (e.g., 5 attempts/min/IP) on auth endpoints. "
                    "Add account lockout, CAPTCHA, and alerting for repeated failures."
                ),
            ))

    def _check_graphql(self):
        gql_paths = ["/graphql", "/api/graphql", "/gql"]
        found_path = next((ep["path"] for ep in self.endpoints_found if ep["path"] in gql_paths), None)
        if not found_path:
            for p in gql_paths:
                try:
                    r = self.client.post(self.base_url + p,
                                         content=GRAPHQL_INTROSPECTION,
                                         headers={"Content-Type": "application/json"})
                    if r.status_code in (200, 400) and "data" in r.text:
                        found_path = p
                        self.graphql_found = True
                        break
                except Exception:
                    pass
        if not found_path:
            return
        try:
            r = self.client.post(self.base_url + found_path,
                                 content=GRAPHQL_INTROSPECTION,
                                 headers={"Content-Type": "application/json"})
            if r.status_code == 200 and '"types"' in r.text:
                self.graphql_found = True
                self._add(Finding(
                    title="GraphQL introspection enabled in production",
                    description=(
                        "The GraphQL endpoint accepts introspection queries, exposing the full "
                        "API schema. Attackers can map all types, fields, queries, and mutations "
                        "to discover unprotected operations."
                    ),
                    severity="medium",
                    cvss_score=5.5,
                    category="API9:2023 - Improper Inventory Management",
                    evidence=f"POST {self.base_url}{found_path} with __schema introspection → HTTP 200",
                    remediation=(
                        "Disable introspection in production. "
                        "Apollo Server: `introspection: false`. "
                        "Graphene: use `IntrospectionDisabledMiddleware`."
                    ),
                ))
        except Exception:
            pass

    def _check_security_headers(self):
        try:
            path = self.endpoints_found[0]["path"] if self.endpoints_found else "/"
            r = self.client.get(self.base_url + path)
            h = {k.lower(): v for k, v in r.headers.items()}

            missing_headers = [
                ("x-content-type-options", "X-Content-Type-Options: nosniff",
                 "Browsers may interpret responses as a different MIME type (MIME sniffing attack).",
                 "low", 3.0),
                ("x-frame-options", "X-Frame-Options: DENY",
                 "Responses can be embedded in iframes, enabling clickjacking attacks.",
                 "low", 3.1),
                ("content-security-policy", "Content-Security-Policy: default-src 'self'",
                 "No CSP is set, leaving consumers vulnerable to XSS when rendering responses.",
                 "low", 3.5),
            ]
            for hdr, fix, desc, sev, score in missing_headers:
                if hdr not in h:
                    self._add(Finding(
                        title=f"Missing security header: {hdr}",
                        description=f"The API does not return `{hdr}`. {desc}",
                        severity=sev,
                        cvss_score=score,
                        category="API8:2023 - Security Misconfiguration",
                        evidence=f"`{hdr}` absent from response headers",
                        remediation=f"Add `{fix}` to all API responses.",
                    ))

            if self.scheme == "https" and "strict-transport-security" not in h:
                self._add(Finding(
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    description=(
                        "The HTTPS API does not set `Strict-Transport-Security`. "
                        "Clients may be downgraded to HTTP by a MITM attacker."
                    ),
                    severity="medium",
                    cvss_score=6.5,
                    category="API8:2023 - Security Misconfiguration",
                    evidence="Strict-Transport-Security header absent",
                    remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                ))
        except Exception:
            pass

    def _check_http_methods(self):
        dangerous = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
        checked = 0
        for ep in self.endpoints_found[:10]:
            if checked >= 5:
                break
            try:
                r = self.client.options(self.base_url + ep["path"])
                allow_raw = r.headers.get("allow", "") or r.headers.get("access-control-allow-methods", "")
                allowed = {m.strip().upper() for m in allow_raw.split(",") if m.strip()}
                exposed = allowed & dangerous

                if "TRACE" in exposed:
                    self._add(Finding(
                        title=f"HTTP TRACE method enabled: {ep['path']}",
                        description=(
                            "TRACE is enabled. Cross-Site Tracing (XST) can expose authentication "
                            "cookies and headers even when HttpOnly flags are set."
                        ),
                        severity="medium",
                        cvss_score=5.8,
                        category="API8:2023 - Security Misconfiguration",
                        evidence=f"OPTIONS {ep['path']} → Allow: {allow_raw}",
                        remediation="Disable HTTP TRACE method at the web server level.",
                    ))
                if (exposed - {"TRACE"}) and any(kw in ep["path"].lower()
                                                  for kw in ("users", "admin", "config", "account")):
                    self._add(Finding(
                        title=f"Potentially unsafe HTTP methods on sensitive endpoint: {ep['path']}",
                        description=(
                            f"Methods {', '.join(sorted(exposed - {'TRACE'}))} are allowed on "
                            f"`{ep['path']}`. Unauthorised modification of data may be possible."
                        ),
                        severity="medium",
                        cvss_score=5.5,
                        category="API5:2023 - Broken Function Level Authorization",
                        evidence=f"OPTIONS {ep['path']} → Allow: {allow_raw}",
                        remediation=(
                            "Restrict HTTP methods to only those required by the business logic. "
                            "Validate function-level authorization for each allowed method."
                        ),
                    ))
                checked += 1
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
