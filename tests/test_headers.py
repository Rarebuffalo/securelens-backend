from unittest.mock import MagicMock

import pytest

from app.services.scanner.headers import HeaderScanner

scanner = HeaderScanner()


def _make_response(headers: dict) -> MagicMock:
    response = MagicMock()
    response.headers = headers
    return response


@pytest.mark.asyncio
async def test_detects_all_missing_headers():
    response = _make_response({})
    issues = await scanner.scan("https://example.com", response)
    issue_texts = [i.issue for i in issues]
    assert any("Content-Security-Policy" in t for t in issue_texts)
    assert any("X-Frame-Options" in t for t in issue_texts)
    assert any("X-Content-Type-Options" in t for t in issue_texts)
    assert any("Referrer-Policy" in t for t in issue_texts)
    assert any("Permissions-Policy" in t for t in issue_texts)
    assert any("Cache-Control" in t for t in issue_texts)
    assert any("COOP" in t for t in issue_texts)
    assert any("CORP" in t for t in issue_texts)
    assert any("COEP" in t for t in issue_texts)


@pytest.mark.asyncio
async def test_detects_unsafe_inline_csp():
    response = _make_response({
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "camera=()",
        "Cache-Control": "no-store",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    })
    issues = await scanner.scan("https://example.com", response)
    assert any("unsafe-inline" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_unsafe_eval_csp():
    response = _make_response({
        "Content-Security-Policy": "default-src 'self' 'unsafe-eval'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "camera=()",
        "Cache-Control": "no-store",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    })
    issues = await scanner.scan("https://example.com", response)
    assert any("unsafe-eval" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_server_disclosure():
    response = _make_response({"Server": "Apache/2.4.41"})
    issues = await scanner.scan("https://example.com", response)
    assert any("Server header" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_x_powered_by():
    response = _make_response({"X-Powered-By": "Express"})
    issues = await scanner.scan("https://example.com", response)
    assert any("X-Powered-By" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_no_issues_with_all_headers():
    response = _make_response({
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "Cache-Control": "no-store",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    })
    issues = await scanner.scan("https://example.com", response)
    assert len(issues) == 0
