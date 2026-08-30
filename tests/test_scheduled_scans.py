import pytest


@pytest.mark.asyncio
async def test_create_scheduled_scan(async_client, auth_headers):
    response = await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com", "schedule": "daily"},
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["url"] == "https://example.com"
    assert data["schedule"] == "daily"
    assert data["is_active"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_create_scheduled_scan_invalid_schedule(async_client, auth_headers):
    response = await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com", "schedule": "hourly"},
        headers=auth_headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_scheduled_scan_duplicate(async_client, auth_headers):
    await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com", "schedule": "daily"},
        headers=auth_headers,
    )
    dup_res = await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com", "schedule": "daily"},
        headers=auth_headers,
    )
    assert dup_res.status_code == 409


@pytest.mark.asyncio
async def test_list_scheduled_scans(async_client, auth_headers):
    await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com/site1", "schedule": "daily"},
        headers=auth_headers,
    )
    await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com/site2", "schedule": "weekly"},
        headers=auth_headers,
    )

    response = await async_client.get("/scheduled-scans", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


@pytest.mark.asyncio
async def test_toggle_scheduled_scan(async_client, auth_headers):
    create_res = await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com/toggle-test", "schedule": "daily"},
        headers=auth_headers,
    )
    scan_id = create_res.json()["id"]

    # Pause
    toggle_res = await async_client.patch(f"/scheduled-scans/{scan_id}/toggle", headers=auth_headers)
    assert toggle_res.status_code == 200
    assert toggle_res.json()["is_active"] is False

    # Resume
    toggle_res2 = await async_client.patch(f"/scheduled-scans/{scan_id}/toggle", headers=auth_headers)
    assert toggle_res2.status_code == 200
    assert toggle_res2.json()["is_active"] is True


@pytest.mark.asyncio
async def test_delete_scheduled_scan(async_client, auth_headers):
    create_res = await async_client.post(
        "/scheduled-scans",
        json={"url": "https://example.com/delete-test", "schedule": "daily"},
        headers=auth_headers,
    )
    scan_id = create_res.json()["id"]

    del_res = await async_client.delete(f"/scheduled-scans/{scan_id}", headers=auth_headers)
    assert del_res.status_code == 204

    # Verify not found
    get_res = await async_client.patch(f"/scheduled-scans/{scan_id}/toggle", headers=auth_headers)
    assert get_res.status_code == 404


@pytest.mark.asyncio
async def test_scheduled_scan_unauthorized(async_client):
    response = await async_client.get("/scheduled-scans")
    assert response.status_code == 401
