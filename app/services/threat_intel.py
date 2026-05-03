"""
Threat Intelligence Service
=============================

Enriches scan results with real-world reputation data from external
threat intelligence feeds. Two providers are integrated:

  1. VirusTotal  — Checks if any of 70+ AV/security vendors have flagged
                   the domain as malicious or suspicious.
                   Free tier: 4 lookups/minute, 500/day
                   Sign up: https://www.virustotal.com/

  2. AbuseIPDB   — Checks if the server's IP has been reported for
                   abuse (spam, attacks, scanning, etc.).
                   Free tier: 1000 lookups/day
                   Sign up: https://www.abuseipdb.com/

Both are OPTIONAL. If the API keys are not set in .env, the lookup is
gracefully skipped and the rest of the scan continues normally.

Usage:
  from app.services.threat_intel import get_threat_intel_summary
  intel = await get_threat_intel_summary("https://example.com")
  # intel is a ThreatIntelReport or None
"""

import logging
import socket
from typing import Optional

import httpx
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic response schema
# ---------------------------------------------------------------------------

class VirusTotalResult(BaseModel):
    """Result from VirusTotal domain reputation lookup."""
    vendor_count: int          # total vendors that checked this domain
    malicious: int             # vendors that flagged it as malicious
    suspicious: int            # vendors that flagged it as suspicious
    harmless: int              # vendors that marked it as clean
    reputation_score: int      # VirusTotal's own reputation score (negative = bad)

class AbuseIPDBResult(BaseModel):
    """Result from AbuseIPDB IP reputation lookup."""
    ip_address: str
    abuse_confidence_score: int   # 0-100; 100 = definitely malicious
    total_reports: int            # how many times this IP has been reported
    country_code: str
    isp: str
    usage_type: str               # e.g. "Data Center/Web Hosting/Transit"

class ThreatIntelReport(BaseModel):
    """
    Aggregated threat intelligence for a scanned URL.
    Both fields are Optional — only populated when the respective API key is set.
    """
    domain: str
    ip_address: Optional[str] = None
    virustotal: Optional[VirusTotalResult] = None
    abuseipdb: Optional[AbuseIPDBResult] = None
    threat_summary: str = "No threat intelligence data available."


# ---------------------------------------------------------------------------
# VirusTotal lookup
# ---------------------------------------------------------------------------

async def check_virustotal(domain: str) -> Optional[VirusTotalResult]:
    """
    Queries the VirusTotal v3 API for domain reputation.

    The domain report endpoint returns counts from 70+ security vendors.
    We extract malicious/suspicious/harmless counts and the overall
    reputation score (a negative number means the community flagged it).
    """
    if not settings.virustotal_api_key:
        return None

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        reputation = data["data"]["attributes"].get("reputation", 0)

        return VirusTotalResult(
            vendor_count=sum(stats.values()),
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            reputation_score=reputation,
        )
    except httpx.HTTPStatusError as e:
        logger.warning(f"VirusTotal lookup failed for {domain}: HTTP {e.response.status_code}")
    except Exception as e:
        logger.warning(f"VirusTotal lookup error for {domain}: {e}")

    return None


# ---------------------------------------------------------------------------
# AbuseIPDB lookup
# ---------------------------------------------------------------------------

async def check_abuseipdb(ip_address: str) -> Optional[AbuseIPDBResult]:
    """
    Queries the AbuseIPDB v2 API for IP address reputation.

    Returns an abuse confidence score (0-100) and metadata about
    the IP address, including ISP and how many times it's been reported.
    """
    if not settings.abuseipdb_api_key:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            d = resp.json()["data"]

        return AbuseIPDBResult(
            ip_address=ip_address,
            abuse_confidence_score=d.get("abuseConfidenceScore", 0),
            total_reports=d.get("totalReports", 0),
            country_code=d.get("countryCode", "Unknown"),
            isp=d.get("isp", "Unknown"),
            usage_type=d.get("usageType", "Unknown"),
        )
    except httpx.HTTPStatusError as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip_address}: HTTP {e.response.status_code}")
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup error for {ip_address}: {e}")

    return None


# ---------------------------------------------------------------------------
# Resolve domain → IP (sync wrapped in executor)
# ---------------------------------------------------------------------------

async def _resolve_ip(domain: str) -> Optional[str]:
    """
    Resolves a domain name to its IPv4 address using the system resolver.
    Runs in a thread pool since socket.gethostbyname is blocking.
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return ip
    except socket.gaierror:
        logger.debug(f"Could not resolve IP for domain: {domain}")
        return None


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

async def get_threat_intel_summary(url: str) -> Optional[ThreatIntelReport]:
    """
    Runs both VirusTotal and AbuseIPDB checks concurrently for a given URL.

    Parameters
    ----------
    url : str
        The full URL that was scanned (e.g. "https://example.com").

    Returns
    -------
    ThreatIntelReport if at least one check ran, otherwise None.

    Example return value:
    {
      "domain": "example.com",
      "ip_address": "93.184.216.34",
      "virustotal": {
        "vendor_count": 82,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 75,
        "reputation_score": 0
      },
      "abuseipdb": {
        "ip_address": "93.184.216.34",
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "country_code": "US",
        "isp": "Edgecast Inc.",
        "usage_type": "Content Delivery Network"
      },
      "threat_summary": "Domain appears clean. No vendor flags on VirusTotal. IP has 0% abuse confidence."
    }
    """
    # Skip entirely if neither key is configured
    if not settings.virustotal_api_key and not settings.abuseipdb_api_key:
        logger.debug("No threat intel keys configured; skipping.")
        return None

    # Extract the bare domain from the URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    if not domain:
        return None

    import asyncio

    # Run IP resolution first (needed for AbuseIPDB)
    ip_address = await _resolve_ip(domain)

    # Run both checks concurrently
    vt_task = asyncio.create_task(check_virustotal(domain))
    ab_task = asyncio.create_task(check_abuseipdb(ip_address)) if ip_address else None

    vt_result = await vt_task
    ab_result = await ab_task if ab_task else None

    # If nothing ran (both keys missing despite the early check above), bail
    if not vt_result and not ab_result:
        return None

    # Build a human-readable summary sentence
    parts = []
    if vt_result:
        if vt_result.malicious > 0:
            parts.append(
                f"⚠️  VirusTotal: {vt_result.malicious}/{vt_result.vendor_count} vendors flagged this domain as malicious."
            )
        else:
            parts.append(
                f"✅ VirusTotal: No malicious flags from {vt_result.vendor_count} vendors."
            )
    if ab_result:
        score = ab_result.abuse_confidence_score
        if score >= 50:
            parts.append(
                f"⚠️  AbuseIPDB: IP {ip_address} has a high abuse confidence score of {score}% "
                f"({ab_result.total_reports} reports)."
            )
        elif score > 0:
            parts.append(
                f"🔶 AbuseIPDB: IP {ip_address} has a low abuse score of {score}% "
                f"({ab_result.total_reports} reports)."
            )
        else:
            parts.append(f"✅ AbuseIPDB: IP {ip_address} has no reported abuse.")

    return ThreatIntelReport(
        domain=domain,
        ip_address=ip_address,
        virustotal=vt_result,
        abuseipdb=ab_result,
        threat_summary=" ".join(parts) if parts else "No threat signals detected.",
    )
