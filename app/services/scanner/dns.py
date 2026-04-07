import asyncio
import logging
from urllib.parse import urlparse

import aiodns
import httpx

from app.schemas.scan import Issue

logger = logging.getLogger(__name__)


class DNSScanner:
    def __init__(self):
        self.resolver = aiodns.DNSResolver(timeout=3.0)

    async def scan(self, url: str) -> list[Issue]:
        issues = []
        domain = self._extract_domain(url)
        if not domain:
            return issues

        tasks = [
            self._check_spf(domain),
            self._check_dmarc(domain),
            self._enumerate_subdomains(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                issues.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"DNS scan error: {result}")

        return issues

    def _extract_domain(self, url: str) -> str | None:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return None

    async def _check_spf(self, domain: str) -> list[Issue]:
        issues = []
        try:
            records = await self.resolver.query(domain, "TXT")
            has_spf = any("v=spf1" in r.text for r in records if r.text)
            if not has_spf:
                issues.append(
                    Issue(
                        issue="Missing SPF Record",
                        severity="Medium",
                        layer="DNS",
                        fix="Add a TXT record with SPF rules (e.g., v=spf1 mx -all) to prevent email spoofing.",
                    )
                )
        except aiodns.error.DNSError as e:
            # Code 4 usually means no record of that type, or Code 1 is domain not found
            if e.args[0] in [1, 4]:
                issues.append(
                    Issue(
                        issue="Missing SPF Record",
                        severity="Medium",
                        layer="DNS",
                        fix="Add a TXT record with SPF rules (e.g., v=spf1 mx -all) to prevent email spoofing.",
                    )
                )
            else:
                logger.debug(f"SPF DNS error for {domain}: {e}")
        return issues

    async def _check_dmarc(self, domain: str) -> list[Issue]:
        issues = []
        dmarc_domain = f"_dmarc.{domain}"
        try:
            records = await self.resolver.query(dmarc_domain, "TXT")
            has_dmarc = any("v=DMARC1" in r.text for r in records if r.text)
            if not has_dmarc:
                issues.append(
                    Issue(
                        issue="Missing DMARC Record",
                        severity="Low",
                        layer="DNS",
                        fix="Add a DMARC TXT record at _dmarc to policy control email spoofing failures.",
                    )
                )
        except aiodns.error.DNSError as e:
            if e.args[0] in [1, 4]:
                issues.append(
                    Issue(
                        issue="Missing DMARC Record",
                        severity="Low",
                        layer="DNS",
                        fix="Add a DMARC TXT record at _dmarc to policy control email spoofing failures.",
                    )
                )
            else:
                logger.debug(f"DMARC DNS error for {domain}: {e}")
        return issues

    async def _enumerate_subdomains(self, domain: str) -> list[Issue]:
        issues = []
        # Query Certificate Transparency logs via crt.sh
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    unique_subs = set()
                    
                    # Extract subdomains
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Handle multiple names separated by newlines
                        for sub in name.split("\n"):
                            sub = sub.strip()
                            if "*" not in sub and sub != domain and sub != f"www.{domain}":
                                unique_subs.add(sub)

                    # Look for risky subdomains
                    keywords = ["dev", "test", "staging", "qa", "admin", "internal", "api", "dashboard"]
                    dev_envs = [sub for sub in unique_subs if any(kw in sub.lower() for kw in keywords)]
                    
                    if dev_envs:
                        env_str = ", ".join(list(dev_envs)[:3])
                        more = len(dev_envs) - 3
                        if more > 0:
                            env_str += f", and {more} more"

                        issues.append(
                            Issue(
                                issue="Exposed Subdomains Detected",
                                severity="Info",
                                layer="DNS",
                                fix=f"Subdomains such as {env_str} are exposed in CT logs. Ensure they are protected and not publicly accessible if they afford sensitive access.",
                            )
                        )
        except Exception as e:
            logger.debug(f"Subdomain enumeration failed for {domain}: {str(e)}")

        return issues
