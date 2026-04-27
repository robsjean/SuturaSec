import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from typing import Optional

import httpx


class AuthStrategy(str, Enum):
    AUTO = "auto"
    FORM_HTML = "form_html"
    JSON_API = "json_api"
    BASIC = "basic"
    PROVIDED_TOKEN = "token"


@dataclass
class AuthSession:
    success: bool
    strategy: AuthStrategy
    cookies: dict = field(default_factory=dict)
    auth_headers: dict = field(default_factory=dict)
    token: Optional[str] = None
    token_type: str = "unknown"
    is_jwt: bool = False
    jwt_payload: Optional[dict] = None
    login_url_used: str = ""
    error: Optional[str] = None
    client: Optional[object] = field(default=None, repr=False)


class _FormParser(HTMLParser):
    """Collects all <form> elements with their input fields."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs):
        d = dict(attrs)
        if tag == "form":
            self._form = {
                "action": d.get("action", ""),
                "method": d.get("method", "post").upper(),
                "inputs": [],
            }
        elif self._form is not None:
            name = d.get("name", "")
            if not name:
                return
            if tag in ("input", "textarea", "select"):
                self._form["inputs"].append({
                    "name": name,
                    "type": d.get("type", "text"),
                    "value": d.get("value", ""),
                })
            elif tag == "button" and d.get("type", "submit") == "submit":
                self._form["inputs"].append({
                    "name": name,
                    "type": "submit",
                    "value": d.get("value", ""),
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


def _extract_token(response: httpx.Response) -> Optional[str]:
    try:
        data = response.json()
    except Exception:
        return None
    fields = [
        "access_token", "token", "accessToken", "jwt",
        "id_token", "auth_token", "authToken", "bearer",
    ]
    wrappers = [None, "data", "result", "user", "auth", "payload"]
    for wrap in wrappers:
        obj = data.get(wrap) if wrap else data
        if isinstance(obj, dict):
            for f in fields:
                v = obj.get(f)
                if isinstance(v, str) and len(v) > 20:
                    return v
    return None


def _auth_succeeded(response: httpx.Response) -> bool:
    if response.status_code in (401, 403, 404):
        return False
    if response.status_code not in range(200, 400):
        return False
    text = (response.text or "").lower()
    for bad in (
        "invalid credentials", "invalid password", "wrong password",
        "authentication failed", "login failed", "bad credentials",
        "identifiants incorrects", "mot de passe incorrect", "unauthorized",
        '"status":"error"', '"success":false',
    ):
        if bad in text:
            return False
    for good in (
        "access_token", "dashboard", "logout", "déconnexion",
        '"success":true', '"status":"ok"', '"status":"success"',
    ):
        if good in text:
            return True
    if _extract_token(response):
        return True
    cookie_hdr = response.headers.get("set-cookie", "")
    if any(s in cookie_hdr.lower() for s in ("session", "token", "auth", "jwt")):
        return True
    return response.status_code in (200, 201)


class UniversalAuthHandler:
    """
    Auto-detects and handles all common web authentication flows:
    HTML form login, JSON REST API, HTTP Basic Auth, pre-provided token.
    """

    _LOGIN_PATHS = [
        "/api/auth/login", "/api/login", "/api/user/login", "/auth/login",
        "/login", "/api/v1/auth/login", "/api/v1/login", "/api/v2/auth/login",
        "/api/v2/login", "/api/token", "/api/auth/token", "/oauth/token",
        "/api/session", "/api/auth", "/api/users/login", "/api/account/login",
        "/api/signin", "/signin", "/api/v1/token", "/api/v1/sessions",
    ]

    _ID_FIELDS = [
        ("email", "password"),
        ("username", "password"),
        ("login", "password"),
        ("user", "password"),
        ("identifier", "password"),
        ("userNameOrEmail", "password"),
        ("user_login", "user_pass"),
    ]

    def __init__(
        self,
        target: str,
        login_identifier: str,
        password: str,
        login_url: Optional[str] = None,
        provided_token: Optional[str] = None,
        timeout: int = 20,
    ):
        self.target = target.rstrip("/")
        self.login_identifier = login_identifier
        self.password = password
        self.login_url = login_url
        self.provided_token = provided_token
        self._client = httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SuturaSec/1.0; Security-Assessment)"},
        )

    def authenticate(self) -> AuthSession:
        if self.provided_token:
            return self._use_token()
        for strategy_fn in (self._try_form, self._try_json, self._try_basic):
            session = strategy_fn()
            if session.success:
                return session
        return AuthSession(
            success=False,
            strategy=AuthStrategy.AUTO,
            error="All authentication strategies failed",
            client=self._client,
        )

    # ── Strategies ────────────────────────────────────────────────────────────

    def _use_token(self) -> AuthSession:
        tok = self.provided_token.strip()
        for prefix in ("bearer ", "Bearer "):
            if tok.startswith(prefix):
                tok = tok[len(prefix):]
                break
        is_jwt = tok.count(".") == 2
        hdr = {"Authorization": f"Bearer {tok}"}
        self._client.headers.update(hdr)
        return AuthSession(
            success=True,
            strategy=AuthStrategy.PROVIDED_TOKEN,
            auth_headers=hdr,
            token=tok,
            token_type="bearer",
            is_jwt=is_jwt,
            jwt_payload=_decode_jwt_payload(tok) if is_jwt else None,
            client=self._client,
        )

    def _try_form(self) -> AuthSession:
        candidates: list[str] = []
        if self.login_url:
            candidates.append(
                self.login_url if "://" in self.login_url else self.target + self.login_url
            )
        candidates += [
            self.target + p
            for p in ("/login", "/signin", "/auth/login", "/user/login", "/account/login", "")
        ]

        for url in candidates:
            try:
                r = self._client.get(url)
            except Exception:
                continue
            if r.status_code not in (200, 302):
                continue

            parser = _FormParser()
            parser.feed(r.text)
            for form in parser.forms:
                if not any(i["type"] == "password" for i in form["inputs"]):
                    continue
                data: dict = {}
                for inp in form["inputs"]:
                    t, n = inp["type"], inp["name"]
                    if t == "password":
                        data[n] = self.password
                    elif t in ("text", "email") or any(
                        k in n.lower() for k in ("user", "email", "login", "mail", "identifier", "name")
                    ):
                        data[n] = self.login_identifier
                    elif t == "hidden":
                        data[n] = inp["value"]
                    elif t == "submit" and n:
                        data[n] = inp["value"]

                action = form["action"]
                if not action:
                    form_url = url
                elif "://" in action:
                    form_url = action
                elif action.startswith("/"):
                    form_url = self.target + action
                else:
                    form_url = url.rsplit("/", 1)[0] + "/" + action

                try:
                    resp = (
                        self._client.get(form_url, params=data)
                        if form["method"] == "GET"
                        else self._client.post(form_url, data=data)
                    )
                    if _auth_succeeded(resp):
                        return self._build_session(resp, AuthStrategy.FORM_HTML, form_url)
                except Exception:
                    continue

        return AuthSession(success=False, strategy=AuthStrategy.FORM_HTML, client=self._client)

    def _try_json(self) -> AuthSession:
        endpoints: list[str] = []
        if self.login_url:
            endpoints.append(
                self.login_url if "://" in self.login_url else self.target + self.login_url
            )
        endpoints += [self.target + p for p in self._LOGIN_PATHS]

        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        for ep in endpoints:
            for id_key, pwd_key in self._ID_FIELDS:
                payload = {id_key: self.login_identifier, pwd_key: self.password}
                try:
                    resp = self._client.post(ep, json=payload, headers=hdrs)
                    if resp.status_code in (200, 201) and _auth_succeeded(resp):
                        return self._build_session(resp, AuthStrategy.JSON_API, ep)
                except Exception:
                    continue

        return AuthSession(success=False, strategy=AuthStrategy.JSON_API, client=self._client)

    def _try_basic(self) -> AuthSession:
        cred = base64.b64encode(f"{self.login_identifier}:{self.password}".encode()).decode()
        hdr = {"Authorization": f"Basic {cred}"}
        try:
            r = self._client.get(self.target, headers=hdr)
            if r.status_code == 200:
                self._client.headers.update(hdr)
                return AuthSession(
                    success=True,
                    strategy=AuthStrategy.BASIC,
                    auth_headers=hdr,
                    token=cred,
                    token_type="basic",
                    login_url_used=self.target,
                    client=self._client,
                )
        except Exception:
            pass
        return AuthSession(success=False, strategy=AuthStrategy.BASIC, client=self._client)

    # ── Helper ────────────────────────────────────────────────────────────────

    def _build_session(
        self, resp: httpx.Response, strategy: AuthStrategy, url: str
    ) -> AuthSession:
        token = _extract_token(resp)
        if not token:
            for k, v in dict(self._client.cookies).items():
                if any(t in k.lower() for t in ("token", "jwt", "auth")) and v.count(".") == 2:
                    token = v
                    break
        is_jwt = bool(token and token.count(".") == 2)
        hdrs: dict = {}
        if token:
            hdrs = {"Authorization": f"Bearer {token}"}
            self._client.headers.update(hdrs)
        return AuthSession(
            success=True,
            strategy=strategy,
            cookies=dict(self._client.cookies),
            auth_headers=hdrs,
            token=token,
            token_type="bearer" if is_jwt else ("cookie" if self._client.cookies else "unknown"),
            is_jwt=is_jwt,
            jwt_payload=_decode_jwt_payload(token) if is_jwt else None,
            login_url_used=url,
            client=self._client,
        )
