from unittest.mock import MagicMock

import pytest

from app.services.scanner.transport import TransportScanner

scanner = TransportScanner()


def _make_response(headers: dict) -> MagicMock:
    response = MagicMock()
    response.headers = headers
    return response


@pytest.mark.asyncio
async def test_detects_no_https():
    response = _make_response({})
    issues = await scanner.scan("http://example.com", response)
    assert any("HTTPS" in i.issue for i in issues)
    assert len(issues) == 1


@pytest.mark.asyncio
async def test_detects_missing_hsts():
    response = _make_response({})
    issues = await scanner.scan("https://example.com", response)
    assert any("HSTS" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_short_hsts_max_age():
    response = _make_response({
        "Strict-Transport-Security": "max-age=3600; includeSubDomains; preload"
    })
    issues = await scanner.scan("https://example.com", response)
    assert any("max-age" in i.issue.lower() for i in issues)


@pytest.mark.asyncio
async def test_detects_missing_includesubdomains():
    response = _make_response({
        "Strict-Transport-Security": "max-age=31536000; preload"
    })
    issues = await scanner.scan("https://example.com", response)
    assert any("includeSubDomains" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_missing_preload():
    response = _make_response({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    })
    issues = await scanner.scan("https://example.com", response)
    assert any("preload" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_missing_upgrade_insecure_requests():
    response = _make_response({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
    })
    issues = await scanner.scan("https://example.com", response)
    assert any("upgrade-insecure-requests" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_good_hsts_no_transport_issues():
    response = _make_response({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; upgrade-insecure-requests",
    })
    issues = await scanner.scan("https://example.com", response)
    assert len(issues) == 0
