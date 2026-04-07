import httpx

from app.schemas.scan import Issue
from app.services.scanner.base import BaseScanner

MIN_HSTS_MAX_AGE = 15768000  # 6 months in seconds


class TransportScanner(BaseScanner):
    async def scan(self, url: str, response: httpx.Response) -> list[Issue]:
        issues: list[Issue] = []
        headers = response.headers

        if not url.startswith("https"):
            issues.append(Issue(
                issue="Website is not using HTTPS",
                severity="Critical",
                layer="Transport Layer",
                fix="Install SSL certificate and redirect HTTP to HTTPS",
            ))
            return issues

        hsts = headers.get("Strict-Transport-Security", "")
        if not hsts:
            issues.append(Issue(
                issue="Missing HSTS header",
                severity="Warning",
                layer="Transport Layer",
                fix="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ))
        else:
            hsts_lower = hsts.lower()

            max_age = 0
            for directive in hsts_lower.split(";"):
                directive = directive.strip()
                if directive.startswith("max-age="):
                    try:
                        max_age = int(directive.split("=", 1)[1])
                    except ValueError:
                        pass

            if max_age < MIN_HSTS_MAX_AGE:
                issues.append(Issue(
                    issue=f"HSTS max-age is too short ({max_age}s, minimum recommended: {MIN_HSTS_MAX_AGE}s)",
                    severity="Warning",
                    layer="Transport Layer",
                    fix="Set HSTS max-age to at least 15768000 (6 months), ideally 31536000 (1 year)",
                ))

            if "includesubdomains" not in hsts_lower:
                issues.append(Issue(
                    issue="HSTS header missing includeSubDomains directive",
                    severity="Info",
                    layer="Transport Layer",
                    fix="Add includeSubDomains to HSTS header to protect all subdomains",
                ))

            if "preload" not in hsts_lower:
                issues.append(Issue(
                    issue="HSTS header missing preload directive",
                    severity="Info",
                    layer="Transport Layer",
                    fix="Add preload to HSTS header and submit to hstspreload.org for browser preload list",
                ))

        csp = headers.get("Content-Security-Policy", "")
        if url.startswith("https") and "upgrade-insecure-requests" not in csp.lower():
            issues.append(Issue(
                issue="CSP does not include upgrade-insecure-requests directive",
                severity="Info",
                layer="Transport Layer",
                fix="Add 'upgrade-insecure-requests' to Content-Security-Policy to auto-upgrade HTTP resources",
            ))

        return issues
