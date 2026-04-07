import logging

import httpx

from app.config import settings
from app.schemas.scan import Issue
from app.services.scanner.base import BaseScanner

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    "/admin",
    "/.env",
    "/.git",
    "/.git/config",
    "/.git/HEAD",
    "/backup",
    "/debug",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/swagger.json",
    "/openapi.json",
    "/api/docs",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/elmah.axd",
    "/trace.axd",
    "/phpinfo.php",
    "/config.php",
    "/wp-config.php.bak",
    "/.well-known/security.txt",
]

ROBOTS_SENSITIVE_KEYWORDS = [
    "/admin",
    "/login",
    "/dashboard",
    "/secret",
    "/private",
    "/backup",
    "/config",
    "/database",
    "/staging",
    "/internal",
    "/api/v",
]


class ExposureScanner(BaseScanner):
    async def scan(self, url: str, response: httpx.Response) -> list[Issue]:
        issues: list[Issue] = []
        base_url = url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.path_check_timeout),
            follow_redirects=True,
        ) as client:
            for path in SENSITIVE_PATHS:
                try:
                    r = await client.get(base_url + path)
                    if r.status_code == 200:
                        issues.append(Issue(
                            issue=f"Sensitive path exposed: {path}",
                            severity="Critical",
                            layer="Exposure Layer",
                            fix=f"Restrict access to {path} using authentication or firewall rules",
                        ))
                except httpx.HTTPError:
                    logger.debug(f"Could not reach {base_url}{path}")

            issues.extend(await self._check_robots_txt(client, base_url))
            issues.extend(await self._check_directory_listing(client, base_url))

        return issues

    async def _check_robots_txt(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Issue]:
        issues: list[Issue] = []
        try:
            r = await client.get(base_url + "/robots.txt")
            if r.status_code == 200:
                content = r.text.lower()
                exposed_paths = []
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            for keyword in ROBOTS_SENSITIVE_KEYWORDS:
                                if keyword in path.lower():
                                    exposed_paths.append(path)
                                    break

                if exposed_paths:
                    paths_str = ", ".join(exposed_paths[:5])
                    issues.append(Issue(
                        issue=f"robots.txt reveals sensitive paths: {paths_str}",
                        severity="Warning",
                        layer="Exposure Layer",
                        fix="Avoid listing sensitive paths in robots.txt; use authentication instead",
                    ))
        except httpx.HTTPError:
            pass

        return issues

    async def _check_directory_listing(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[Issue]:
        issues: list[Issue] = []
        test_paths = ["/images/", "/assets/", "/static/", "/uploads/"]

        for path in test_paths:
            try:
                r = await client.get(base_url + path)
                if r.status_code == 200:
                    body = r.text.lower()
                    if "index of" in body or "directory listing" in body or ("<pre>" in body and "parent directory" in body):
                        issues.append(Issue(
                            issue=f"Directory listing enabled at {path}",
                            severity="Warning",
                            layer="Exposure Layer",
                            fix=f"Disable directory listing for {path} in your web server configuration",
                        ))
                        break
            except httpx.HTTPError:
                pass

        return issues
