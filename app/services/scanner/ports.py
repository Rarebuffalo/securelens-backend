import asyncio
import logging
from urllib.parse import urlparse

from app.schemas.scan import Issue

logger = logging.getLogger(__name__)

# High-risk ports that generally shouldn't be publicly exposed
HIGH_RISK_PORTS = {
    22: "SSH",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    11211: "Memcached",
    9200: "Elasticsearch",
}


class PortScanner:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    async def scan(self, url: str) -> list[Issue]:
        issues = []
        domain = self._extract_domain(url)
        if not domain:
            return issues

        tasks = [
            self._check_port(domain, port, service)
            for port, service in HIGH_RISK_PORTS.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Issue):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.debug(f"Port scanning exception: {result}")

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

    async def _check_port(self, domain: str, port: int, service: str) -> Issue | None:
        try:
            # Short timeout ensuring minimal scanning latency overhead
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()

            return Issue(
                issue=f"Exposed Database/Service Port: {port} ({service})",
                severity="Critical",
                layer="Network",
                fix=f"Close port {port} to the public internet. Use a VPN, VPC peering, or strict IP whitelisting to access {service}.",
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Normal: port is either closed, filtered, or timing out.
            return None
        except Exception as e:
            logger.debug(f"Unexpected error validating port {port} on {domain}: {e}")
            return None
