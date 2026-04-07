import logging
from http.cookies import SimpleCookie

import httpx

from app.schemas.scan import Issue
from app.services.scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class CookieScanner(BaseScanner):
    async def scan(self, url: str, response: httpx.Response) -> list[Issue]:
        issues: list[Issue] = []
        is_https = url.startswith("https")

        raw_cookies = response.headers.multi_items()
        set_cookie_headers = [
            value for key, value in raw_cookies if key.lower() == "set-cookie"
        ]

        if not set_cookie_headers:
            return issues

        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()

            cookie = SimpleCookie()
            try:
                cookie.load(cookie_str)
            except Exception:
                logger.debug(f"Could not parse cookie: {cookie_str[:80]}")
                continue

            for name, morsel in cookie.items():
                if "httponly" not in cookie_lower:
                    issues.append(Issue(
                        issue=f"Cookie '{name}' missing HttpOnly flag",
                        severity="Warning",
                        layer="Cookie Security",
                        fix=f"Set the HttpOnly flag on cookie '{name}' to prevent JavaScript access",
                    ))

                if "; secure" not in cookie_lower:
                    if is_https:
                        issues.append(Issue(
                            issue=f"Cookie '{name}' missing Secure flag",
                            severity="Warning",
                            layer="Cookie Security",
                            fix=f"Set the Secure flag on cookie '{name}' to ensure it is only sent over HTTPS",
                        ))

                samesite_value = morsel.get("samesite", "").lower()
                if not samesite_value:
                    issues.append(Issue(
                        issue=f"Cookie '{name}' missing SameSite attribute",
                        severity="Warning",
                        layer="Cookie Security",
                        fix=f"Set SameSite=Lax or SameSite=Strict on cookie '{name}' to prevent CSRF attacks",
                    ))
                elif samesite_value == "none":
                    if "; secure" not in cookie_lower:
                        issues.append(Issue(
                            issue=f"Cookie '{name}' has SameSite=None without Secure flag",
                            severity="Critical",
                            layer="Cookie Security",
                            fix=f"Cookies with SameSite=None must also have the Secure flag set",
                        ))

        return issues
