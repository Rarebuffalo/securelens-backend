import httpx

from app.schemas.scan import Issue
from app.services.scanner.base import BaseScanner


class HeaderScanner(BaseScanner):
    async def scan(self, url: str, response: httpx.Response) -> list[Issue]:
        issues: list[Issue] = []
        headers = response.headers

        if "Content-Security-Policy" not in headers:
            issues.append(Issue(
                issue="Missing Content-Security-Policy header",
                severity="Warning",
                layer="Server Config Layer",
                fix="Add header: Content-Security-Policy: default-src 'self';",
            ))
        else:
            csp = headers["Content-Security-Policy"]
            if "'unsafe-inline'" in csp:
                issues.append(Issue(
                    issue="Content-Security-Policy allows 'unsafe-inline'",
                    severity="Warning",
                    layer="Server Config Layer",
                    fix="Remove 'unsafe-inline' from CSP and use nonces or hashes for inline scripts/styles",
                ))
            if "'unsafe-eval'" in csp:
                issues.append(Issue(
                    issue="Content-Security-Policy allows 'unsafe-eval'",
                    severity="Warning",
                    layer="Server Config Layer",
                    fix="Remove 'unsafe-eval' from CSP to prevent dynamic code execution via eval()",
                ))
            if "*" in csp.split():
                issues.append(Issue(
                    issue="Content-Security-Policy uses wildcard (*) source",
                    severity="Warning",
                    layer="Server Config Layer",
                    fix="Replace wildcard (*) in CSP with specific trusted domains",
                ))

        if "X-Frame-Options" not in headers:
            issues.append(Issue(
                issue="Missing X-Frame-Options header",
                severity="Warning",
                layer="Server Config Layer",
                fix="Add header: X-Frame-Options: SAMEORIGIN",
            ))

        if "X-Content-Type-Options" not in headers:
            issues.append(Issue(
                issue="Missing X-Content-Type-Options header",
                severity="Warning",
                layer="Server Config Layer",
                fix="Add header: X-Content-Type-Options: nosniff",
            ))

        if "Referrer-Policy" not in headers:
            issues.append(Issue(
                issue="Missing Referrer-Policy header",
                severity="Info",
                layer="Server Config Layer",
                fix="Add header: Referrer-Policy: strict-origin-when-cross-origin",
            ))

        if "Permissions-Policy" not in headers:
            issues.append(Issue(
                issue="Missing Permissions-Policy header",
                severity="Info",
                layer="Server Config Layer",
                fix="Add header: Permissions-Policy: geolocation=(), camera=(), microphone=()",
            ))

        if headers.get("Access-Control-Allow-Origin") == "*":
            issues.append(Issue(
                issue="CORS allows all origins (*)",
                severity="Warning",
                layer="Server Config Layer",
                fix="Restrict Access-Control-Allow-Origin to trusted domains",
            ))

        server = headers.get("Server", "")
        if server:
            issues.append(Issue(
                issue=f"Server header discloses technology: {server}",
                severity="Info",
                layer="Server Config Layer",
                fix="Remove or obfuscate the Server header to prevent information disclosure",
            ))

        if "X-Powered-By" in headers:
            issues.append(Issue(
                issue=f"X-Powered-By header discloses technology: {headers['X-Powered-By']}",
                severity="Info",
                layer="Server Config Layer",
                fix="Remove the X-Powered-By header to prevent information disclosure",
            ))

        cache_control = headers.get("Cache-Control", "")
        if not cache_control:
            issues.append(Issue(
                issue="Missing Cache-Control header",
                severity="Info",
                layer="Server Config Layer",
                fix="Add Cache-Control header with appropriate directives (e.g., no-store for sensitive pages)",
            ))
        elif "no-store" not in cache_control.lower() and "private" not in cache_control.lower():
            issues.append(Issue(
                issue="Cache-Control does not prevent caching of potentially sensitive content",
                severity="Info",
                layer="Server Config Layer",
                fix="Add 'no-store' or 'private' to Cache-Control for pages with sensitive data",
            ))

        if "Cross-Origin-Opener-Policy" not in headers:
            issues.append(Issue(
                issue="Missing Cross-Origin-Opener-Policy (COOP) header",
                severity="Info",
                layer="Server Config Layer",
                fix="Add header: Cross-Origin-Opener-Policy: same-origin",
            ))

        if "Cross-Origin-Resource-Policy" not in headers:
            issues.append(Issue(
                issue="Missing Cross-Origin-Resource-Policy (CORP) header",
                severity="Info",
                layer="Server Config Layer",
                fix="Add header: Cross-Origin-Resource-Policy: same-origin",
            ))

        if "Cross-Origin-Embedder-Policy" not in headers:
            issues.append(Issue(
                issue="Missing Cross-Origin-Embedder-Policy (COEP) header",
                severity="Info",
                layer="Server Config Layer",
                fix="Add header: Cross-Origin-Embedder-Policy: require-corp",
            ))

        return issues
