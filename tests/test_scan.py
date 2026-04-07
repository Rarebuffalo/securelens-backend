import pytest


@pytest.mark.asyncio
async def test_scan_rejects_invalid_url(async_client):
    response = await async_client.post("/scan", json={"url": "not-a-url"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_rejects_localhost(async_client):
    response = await async_client.post("/scan", json={"url": "http://localhost:8000"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_rejects_private_ip(async_client):
    response = await async_client.post("/scan", json={"url": "http://192.168.1.1"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_valid_url(async_client):
    response = await async_client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code in (200, 502)
    data = response.json()
    assert "security_score" in data or "error" in data


@pytest.mark.asyncio
async def test_scan_missing_url(async_client):
    response = await async_client.post("/scan", json={})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_scan_saves_when_authenticated(async_client, test_user, auth_headers):
    response = await async_client.post(
        "/scan",
        json={"url": "https://example.com"},
        headers=auth_headers,
    )
    if response.status_code == 200:
        data = response.json()
        assert data["id"] is not None
        assert data["created_at"] is not None


@pytest.mark.asyncio
async def test_scan_no_save_when_anonymous(async_client):
    response = await async_client.post("/scan", json={"url": "https://example.com"})
    if response.status_code == 200:
        data = response.json()
        assert data["id"] is None
