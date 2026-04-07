import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanResult


async def _create_scan(user_id: str) -> None:
    from tests.conftest import TestSessionLocal
    async with TestSessionLocal() as session:
        scan = ScanResult(
            user_id=user_id,
            url="https://example.com",
            security_score=85,
            layers={"Transport Layer": {"issues": 1, "status": "yellow"}},
            issues=[{"issue": "Missing HSTS", "severity": "Warning", "layer": "Transport Layer", "fix": "Add HSTS"}],
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan


@pytest.mark.asyncio
async def test_list_scans_empty(async_client, test_user, auth_headers):
    response = await async_client.get("/scans", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["scans"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_list_scans_with_results(async_client, test_user, auth_headers):
    scan = await _create_scan(test_user.id)

    response = await async_client.get("/scans", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert len(data["scans"]) == 1
    assert data["scans"][0]["url"] == "https://example.com"
    assert data["scans"][0]["security_score"] == 85


@pytest.mark.asyncio
async def test_list_scans_pagination(async_client, test_user, auth_headers):
    for _ in range(5):
        await _create_scan(test_user.id)

    response = await async_client.get("/scans?page=1&per_page=2", headers=auth_headers)
    data = response.json()
    assert data["total"] == 5
    assert len(data["scans"]) == 2
    assert data["page"] == 1
    assert data["per_page"] == 2


@pytest.mark.asyncio
async def test_get_scan_by_id(async_client, test_user, auth_headers):
    scan = await _create_scan(test_user.id)

    response = await async_client.get(f"/scans/{scan.id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://example.com"
    assert data["security_score"] == 85
    assert len(data["issues"]) == 1


@pytest.mark.asyncio
async def test_get_scan_not_found(async_client, test_user, auth_headers):
    response = await async_client.get("/scans/nonexistent", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_scan(async_client, test_user, auth_headers):
    scan = await _create_scan(test_user.id)

    response = await async_client.delete(f"/scans/{scan.id}", headers=auth_headers)
    assert response.status_code == 204

    response = await async_client.get(f"/scans/{scan.id}", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_scans_unauthorized(async_client):
    response = await async_client.get("/scans")
    assert response.status_code == 401
