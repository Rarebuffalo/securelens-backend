import pytest


@pytest.mark.asyncio
async def test_create_api_key(async_client, auth_headers):
    response = await async_client.post(
        "/api-keys",
        json={"name": "CI Pipeline Key"},
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "CI Pipeline Key"
    assert data["key"].startswith("sl_")
    assert data["key_prefix"].startswith("sl_")
    assert "id" in data


@pytest.mark.asyncio
async def test_list_api_keys(async_client, auth_headers):
    await async_client.post(
        "/api-keys",
        json={"name": "Key 1"},
        headers=auth_headers,
    )
    await async_client.post(
        "/api-keys",
        json={"name": "Key 2"},
        headers=auth_headers,
    )

    response = await async_client.get("/api-keys", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Verify raw key is NOT exposed in list response
    for item in data:
        assert "key" not in item
        assert "hashed_key" not in item
        assert "key_prefix" in item


@pytest.mark.asyncio
async def test_delete_api_key(async_client, auth_headers):
    create_res = await async_client.post(
        "/api-keys",
        json={"name": "Key To Delete"},
        headers=auth_headers,
    )
    key_id = create_res.json()["id"]

    del_res = await async_client.delete(f"/api-keys/{key_id}", headers=auth_headers)
    assert del_res.status_code == 204

    # Verify key is gone
    list_res = await async_client.get("/api-keys", headers=auth_headers)
    assert len(list_res.json()) == 0


@pytest.mark.asyncio
async def test_delete_nonexistent_api_key(async_client, auth_headers):
    response = await async_client.delete("/api-keys/nonexistent-id", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_api_key_unauthorized(async_client):
    response = await async_client.get("/api-keys")
    assert response.status_code == 401
