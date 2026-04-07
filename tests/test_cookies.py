from unittest.mock import MagicMock

import pytest

from app.services.scanner.cookies import CookieScanner

scanner = CookieScanner()


def _make_response(set_cookie_headers: list[str]) -> MagicMock:
    items = [("content-type", "text/html")]
    for cookie in set_cookie_headers:
        items.append(("set-cookie", cookie))
    response = MagicMock()
    response.headers.multi_items.return_value = items
    return response


@pytest.mark.asyncio
async def test_no_cookies_returns_empty():
    response = _make_response([])
    issues = await scanner.scan("https://example.com", response)
    assert issues == []


@pytest.mark.asyncio
async def test_detects_missing_httponly():
    response = _make_response(["session=abc123; Path=/; Secure; SameSite=Lax"])
    issues = await scanner.scan("https://example.com", response)
    assert any("HttpOnly" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_missing_secure():
    response = _make_response(["session=abc123; Path=/; HttpOnly; SameSite=Lax"])
    issues = await scanner.scan("https://example.com", response)
    assert any("Secure" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_missing_samesite():
    response = _make_response(["session=abc123; Path=/; HttpOnly; Secure"])
    issues = await scanner.scan("https://example.com", response)
    assert any("SameSite" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_detects_samesite_none_without_secure():
    response = _make_response(["session=abc123; Path=/; HttpOnly; SameSite=None"])
    issues = await scanner.scan("https://example.com", response)
    assert any("SameSite=None" in i.issue for i in issues)


@pytest.mark.asyncio
async def test_secure_cookie_passes():
    response = _make_response(["session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"])
    issues = await scanner.scan("https://example.com", response)
    assert len(issues) == 0


@pytest.mark.asyncio
async def test_skips_secure_check_for_http():
    response = _make_response(["session=abc123; Path=/; HttpOnly; SameSite=Lax"])
    issues = await scanner.scan("http://example.com", response)
    assert not any("Secure flag" in i.issue for i in issues)
