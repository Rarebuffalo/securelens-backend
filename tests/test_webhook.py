import pytest


@pytest.mark.asyncio
async def test_create_webhook(async_client, auth_headers):
    response = await async_client.post(
        "/webhooks",
        json={"target_url": "https://example.com/webhook", "secret_key": "my-secret-key"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_url"] == "https://example.com/webhook"
    assert data["is_active"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_create_webhook_auto_secret(async_client, auth_headers):
    response = await async_client.post(
        "/webhooks",
        json={"target_url": "https://example.com/webhook2"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_url"] == "https://example.com/webhook2"
    assert data["is_active"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_list_webhooks(async_client, auth_headers):
    # Create two webhooks
    await async_client.post(
        "/webhooks",
        json={"target_url": "https://example.com/hook1"},
        headers=auth_headers,
    )
    await async_client.post(
        "/webhooks",
        json={"target_url": "https://example.com/hook2"},
        headers=auth_headers,
    )

    response = await async_client.get("/webhooks", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


@pytest.mark.asyncio
async def test_delete_webhook(async_client, auth_headers):
    create_res = await async_client.post(
        "/webhooks",
        json={"target_url": "https://example.com/to-delete"},
        headers=auth_headers,
    )
    hook_id = create_res.json()["id"]

    delete_res = await async_client.delete(f"/webhooks/{hook_id}", headers=auth_headers)
    assert delete_res.status_code == 200

    list_res = await async_client.get("/webhooks", headers=auth_headers)
    assert len(list_res.json()) == 0


@pytest.mark.asyncio
async def test_delete_nonexistent_webhook(async_client, auth_headers):
    response = await async_client.delete("/webhooks/nonexistent-id", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_webhook_unauthorized(async_client):
    response = await async_client.get("/webhooks")
    assert response.status_code == 401
