"""
Web URL Scanner
===============
Runs the full HTTP security check suite against a live URL.
Lifted from the backend scanner/ services — no FastAPI dependency.

Checks:
  1. Transport (HTTPS, HSTS)
  2. Security Headers (CSP, X-Frame-Options, etc.)
  3. Cookie flags (HttpOnly, Secure, SameSite)
  4. Exposed sensitive paths (.env, /admin, etc.)
  5. SSL certificate validity
"""

import asyncio
import ssl
import socket
import datetime
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/admin", "/admin/", "/wp-admin/",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.git/config", "/.git/HEAD",
    "/config.yml", "/config.yaml", "/config.json",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/robots.txt", "/sitemap.xml",   # not dangerous but worth noting
    "/.DS_Store",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env",
    "/__debug__/",
]

MIN_HSTS_MAX_AGE = 15_768_000  # 6 months


@dataclass
class WebIssue:
    issue: str
    severity: str    # Critical | Warning | Info
    layer: str
    fix: str


@dataclass
class WebScanResult:
    url: str
    reachable: bool = True
    issues: list[WebIssue] = field(default_factory=list)
    ai_summary: str = ""
    score: int = 100
    grade: str = "A"
    ssl_expiry_days: Optional[int] = None
    exposed_paths: list[str] = field(default_factory=list)

    def compute_score(self) -> None:
        weights = {"Critical": 15, "Warning": 5, "Info": 2}
        deduction = sum(weights.get(i.severity, 0) for i in self.issues)
        self.score = max(100 - deduction, 0)
        self.grade = _score_to_grade(self.score)


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


async def scan_url(url: str, timeout: int = 10) -> WebScanResult:
    """Run all web security checks against the given URL."""
    result = WebScanResult(url=url)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            verify=False,  # we do our own cert check
        ) as client:
            response = await client.get(url)

        _check_transport(url, response, result)
        _check_headers(url, response, result)
        _check_cookies(url, response, result)
        await _check_exposed_paths(url, result, timeout)
        _check_ssl(url, result)

    except httpx.ConnectError:
        result.reachable = False
        result.issues.append(WebIssue(
            issue="Could not connect to host",
            severity="Critical",
            layer="Transport Layer",
            fix="Verify the URL is correct and the server is running",
        ))
    except Exception as e:
        logger.error(f"Web scan error: {e}")
        result.reachable = False

    result.compute_score()
    return result


# ── Individual checkers ────────────────────────────────────────────────────────

def _check_transport(url: str, response: httpx.Response, result: WebScanResult) -> None:
    headers = response.headers

    if not url.startswith("https"):
        result.issues.append(WebIssue(
            issue="Site is not using HTTPS",
            severity="Critical",
            layer="Transport Layer",
            fix="Install an SSL certificate and redirect all HTTP traffic to HTTPS",
        ))
        return

    hsts = headers.get("Strict-Transport-Security", "")
    if not hsts:
        result.issues.append(WebIssue(
            issue="Missing HSTS (Strict-Transport-Security) header",
            severity="Warning",
            layer="Transport Layer",
            fix="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        ))
    else:
        max_age = 0
        for directive in hsts.lower().split(";"):
            d = directive.strip()
            if d.startswith("max-age="):
                try:
                    max_age = int(d.split("=", 1)[1])
                except ValueError:
                    pass
        if max_age < MIN_HSTS_MAX_AGE:
            result.issues.append(WebIssue(
                issue=f"HSTS max-age is too short ({max_age}s)",
                severity="Warning",
                layer="Transport Layer",
                fix="Set HSTS max-age to at least 31536000 (1 year)",
            ))
        if "includesubdomains" not in hsts.lower():
            result.issues.append(WebIssue(
                issue="HSTS missing includeSubDomains",
                severity="Info",
                layer="Transport Layer",
                fix="Add includeSubDomains to the HSTS header",
            ))


def _check_headers(url: str, response: httpx.Response, result: WebScanResult) -> None:
    h = response.headers

    if "Content-Security-Policy" not in h:
        result.issues.append(WebIssue(
            issue="Missing Content-Security-Policy header",
            severity="Warning",
            layer="Security Headers",
            fix="Add: Content-Security-Policy: default-src 'self';",
        ))
    else:
        csp = h["Content-Security-Policy"]
        if "'unsafe-inline'" in csp:
            result.issues.append(WebIssue(
                issue="CSP allows 'unsafe-inline'",
                severity="Warning",
                layer="Security Headers",
                fix="Remove 'unsafe-inline' from CSP; use nonces or hashes instead",
            ))
        if "'unsafe-eval'" in csp:
            result.issues.append(WebIssue(
                issue="CSP allows 'unsafe-eval'",
                severity="Warning",
                layer="Security Headers",
                fix="Remove 'unsafe-eval' from CSP to prevent eval()-based code execution",
            ))

    if "X-Frame-Options" not in h:
        result.issues.append(WebIssue(
            issue="Missing X-Frame-Options header",
            severity="Warning",
            layer="Security Headers",
            fix="Add: X-Frame-Options: SAMEORIGIN",
        ))

    if "X-Content-Type-Options" not in h:
        result.issues.append(WebIssue(
            issue="Missing X-Content-Type-Options header",
            severity="Warning",
            layer="Security Headers",
            fix="Add: X-Content-Type-Options: nosniff",
        ))

    if "Referrer-Policy" not in h:
        result.issues.append(WebIssue(
            issue="Missing Referrer-Policy header",
            severity="Info",
            layer="Security Headers",
            fix="Add: Referrer-Policy: strict-origin-when-cross-origin",
        ))

    if "Permissions-Policy" not in h:
        result.issues.append(WebIssue(
            issue="Missing Permissions-Policy header",
            severity="Info",
            layer="Security Headers",
            fix="Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        ))

    if h.get("Access-Control-Allow-Origin") == "*":
        result.issues.append(WebIssue(
            issue="CORS allows all origins (*)",
            severity="Warning",
            layer="Security Headers",
            fix="Restrict Access-Control-Allow-Origin to trusted domains",
        ))

    server = h.get("Server", "")
    if server:
        result.issues.append(WebIssue(
            issue=f"Server header reveals technology: {server}",
            severity="Info",
            layer="Security Headers",
            fix="Remove or mask the Server header",
        ))

    if "X-Powered-By" in h:
        result.issues.append(WebIssue(
            issue=f"X-Powered-By header reveals stack: {h['X-Powered-By']}",
            severity="Info",
            layer="Security Headers",
            fix="Remove the X-Powered-By header",
        ))


def _check_cookies(url: str, response: httpx.Response, result: WebScanResult) -> None:
    from http.cookies import SimpleCookie
    is_https = url.startswith("https")
    raw_cookies = response.headers.multi_items()
    set_cookie_headers = [v for k, v in raw_cookies if k.lower() == "set-cookie"]

    for cookie_str in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_str)
        except Exception:
            continue
        cookie_lower = cookie_str.lower()
        for name, _ in cookie.items():
            if "httponly" not in cookie_lower:
                result.issues.append(WebIssue(
                    issue=f"Cookie '{name}' missing HttpOnly flag",
                    severity="Warning",
                    layer="Cookie Security",
                    fix=f"Set HttpOnly on cookie '{name}' to prevent JS access",
                ))
            if is_https and "; secure" not in cookie_lower:
                result.issues.append(WebIssue(
                    issue=f"Cookie '{name}' missing Secure flag",
                    severity="Warning",
                    layer="Cookie Security",
                    fix=f"Set Secure flag on cookie '{name}'",
                ))
            if "samesite" not in cookie_lower:
                result.issues.append(WebIssue(
                    issue=f"Cookie '{name}' missing SameSite attribute",
                    severity="Warning",
                    layer="Cookie Security",
                    fix=f"Set SameSite=Lax or SameSite=Strict on cookie '{name}'",
                ))


async def _check_exposed_paths(url: str, result: WebScanResult, timeout: int) -> None:
    base = url.rstrip("/")
    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        async def check_path(path: str):
            try:
                r = await client.get(base + path)
                if r.status_code == 200 and path not in ("/robots.txt", "/sitemap.xml"):
                    result.exposed_paths.append(path)
                    result.issues.append(WebIssue(
                        issue=f"Sensitive path exposed: {path}",
                        severity="Critical" if ".env" in path or ".git" in path else "Warning",
                        layer="Exposure",
                        fix=f"Block or restrict access to {path} via your web server config",
                    ))
            except Exception:
                pass

        await asyncio.gather(*(check_path(p) for p in SENSITIVE_PATHS))


def _check_ssl(url: str, result: WebScanResult) -> None:
    if not url.startswith("https"):
        return
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=5), server_hostname=hostname) as s:
            cert = s.getpeercert()
            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                result.ssl_expiry_days = days_left
                if days_left < 14:
                    result.issues.append(WebIssue(
                        issue=f"SSL certificate expires in {days_left} days",
                        severity="Critical",
                        layer="SSL/TLS",
                        fix="Renew the SSL certificate immediately",
                    ))
                elif days_left < 30:
                    result.issues.append(WebIssue(
                        issue=f"SSL certificate expires soon ({days_left} days)",
                        severity="Warning",
                        layer="SSL/TLS",
                        fix="Renew the SSL certificate within the next 30 days",
                    ))
    except ssl.SSLCertVerificationError:
        result.issues.append(WebIssue(
            issue="SSL certificate is invalid or self-signed",
            severity="Critical",
            layer="SSL/TLS",
            fix="Install a valid SSL certificate from a trusted CA (e.g. Let's Encrypt)",
        ))
    except Exception as e:
        logger.debug(f"SSL check error: {e}")
