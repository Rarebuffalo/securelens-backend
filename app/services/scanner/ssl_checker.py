import asyncio
import datetime
import logging
import socket
import ssl
from urllib.parse import urlparse

import httpx

from app.schemas.scan import Issue
from app.services.scanner.base import BaseScanner

logger = logging.getLogger(__name__)

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1"}


def _check_ssl(hostname: str, port: int) -> dict:
    result: dict = {
        "error": None,
        "cert": None,
        "tls_version": None,
        "self_signed": False,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["cert"] = ssock.getpeercert()
                result["tls_version"] = ssock.version()
    except ssl.SSLCertVerificationError as e:
        error_msg = str(e)
        result["error"] = error_msg

        if "self-signed" in error_msg.lower() or "self signed" in error_msg.lower():
            result["self_signed"] = True

        try:
            ctx_no_verify = ssl.create_default_context()
            ctx_no_verify.check_hostname = False
            ctx_no_verify.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx_no_verify.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result["tls_version"] = ssock.version()
        except Exception:
            pass
    except (socket.timeout, socket.gaierror, OSError) as e:
        result["error"] = str(e)

    return result


class SSLScanner(BaseScanner):
    async def scan(self, url: str, response: httpx.Response) -> list[Issue]:
        issues: list[Issue] = []
        parsed = urlparse(url)

        if parsed.scheme != "https":
            return issues

        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return issues

        try:
            result = await asyncio.to_thread(_check_ssl, hostname, port)
        except Exception as e:
            logger.warning(f"SSL check failed for {hostname}: {e}")
            return issues

        if result["self_signed"]:
            issues.append(Issue(
                issue="SSL certificate is self-signed",
                severity="Critical",
                layer="SSL/TLS Layer",
                fix="Obtain a valid SSL certificate from a trusted Certificate Authority (e.g., Let's Encrypt)",
            ))

        if result["error"] and not result["self_signed"]:
            issues.append(Issue(
                issue=f"SSL certificate verification failed: {result['error'][:120]}",
                severity="Critical",
                layer="SSL/TLS Layer",
                fix="Ensure the SSL certificate is valid, not expired, and issued by a trusted CA",
            ))

        cert = result.get("cert")
        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()

                    if expiry < now:
                        issues.append(Issue(
                            issue="SSL certificate has expired",
                            severity="Critical",
                            layer="SSL/TLS Layer",
                            fix="Renew the SSL certificate immediately",
                        ))
                    elif (expiry - now).days < 30:
                        issues.append(Issue(
                            issue=f"SSL certificate expires in {(expiry - now).days} days",
                            severity="Warning",
                            layer="SSL/TLS Layer",
                            fix="Renew the SSL certificate before it expires",
                        ))
                except ValueError:
                    logger.debug(f"Could not parse cert expiry: {not_after}")

            subject = cert.get("subject", ())
            issuer = cert.get("issuer", ())
            if subject and issuer and subject == issuer:
                if not result["self_signed"]:
                    issues.append(Issue(
                        issue="SSL certificate is self-signed",
                        severity="Critical",
                        layer="SSL/TLS Layer",
                        fix="Obtain a valid SSL certificate from a trusted Certificate Authority",
                    ))

        tls_version = result.get("tls_version")
        if tls_version and tls_version in WEAK_TLS_VERSIONS:
            issues.append(Issue(
                issue=f"Server supports weak TLS version: {tls_version}",
                severity="Critical",
                layer="SSL/TLS Layer",
                fix="Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2 or higher",
            ))

        return issues
