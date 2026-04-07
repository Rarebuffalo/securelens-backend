import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.services.scanner.ssl_checker import SSLScanner, _check_ssl

scanner = SSLScanner()


@pytest.mark.asyncio
async def test_skips_http_urls():
    response = MagicMock()
    issues = await scanner.scan("http://example.com", response)
    assert issues == []


@pytest.mark.asyncio
async def test_detects_self_signed():
    response = MagicMock()
    mock_result = {
        "error": "self-signed certificate",
        "cert": None,
        "tls_version": "TLSv1.3",
        "self_signed": True,
    }
    with patch("app.services.scanner.ssl_checker.asyncio.to_thread", return_value=mock_result):
        issues = await scanner.scan("https://self-signed.example.com", response)
    assert any("self-signed" in i.issue.lower() for i in issues)


@pytest.mark.asyncio
async def test_detects_weak_tls():
    response = MagicMock()
    future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_result = {
        "error": None,
        "cert": {
            "notAfter": future_date,
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('commonName', 'CA'),),),
        },
        "tls_version": "TLSv1.1",
        "self_signed": False,
    }
    with patch("app.services.scanner.ssl_checker.asyncio.to_thread", return_value=mock_result):
        issues = await scanner.scan("https://example.com", response)
    assert any("weak TLS" in i.issue.lower() or "tls" in i.issue.lower() for i in issues)


@pytest.mark.asyncio
async def test_detects_expiring_soon():
    response = MagicMock()
    soon_date = (datetime.datetime.utcnow() + datetime.timedelta(days=15)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_result = {
        "error": None,
        "cert": {
            "notAfter": soon_date,
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('commonName', 'CA'),),),
        },
        "tls_version": "TLSv1.3",
        "self_signed": False,
    }
    with patch("app.services.scanner.ssl_checker.asyncio.to_thread", return_value=mock_result):
        issues = await scanner.scan("https://example.com", response)
    assert any("expires in" in i.issue.lower() for i in issues)


@pytest.mark.asyncio
async def test_no_issues_for_valid_cert():
    response = MagicMock()
    future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_result = {
        "error": None,
        "cert": {
            "notAfter": future_date,
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('commonName', 'Let\'s Encrypt'),),),
        },
        "tls_version": "TLSv1.3",
        "self_signed": False,
    }
    with patch("app.services.scanner.ssl_checker.asyncio.to_thread", return_value=mock_result):
        issues = await scanner.scan("https://example.com", response)
    assert len(issues) == 0
