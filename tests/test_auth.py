import pytest


@pytest.mark.asyncio
async def test_register(async_client):
    response = await async_client.post("/auth/register", json={
        "email": "new@example.com",
        "username": "newuser",
        "password": "securepass123",
    })
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client, test_user):
    response = await async_client.post("/auth/register", json={
        "email": "test@example.com",
        "username": "different",
        "password": "securepass123",
    })
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_duplicate_username(async_client, test_user):
    response = await async_client.post("/auth/register", json={
        "email": "different@example.com",
        "username": "testuser",
        "password": "securepass123",
    })
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_short_password(async_client):
    response = await async_client.post("/auth/register", json={
        "email": "new@example.com",
        "username": "newuser",
        "password": "short",
    })
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email(async_client):
    response = await async_client.post("/auth/register", json={
        "email": "not-an-email",
        "username": "newuser",
        "password": "securepass123",
    })
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login(async_client, test_user):
    response = await async_client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "testpassword123",
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data


@pytest.mark.asyncio
async def test_login_wrong_password(async_client, test_user):
    response = await async_client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "wrongpassword",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_email(async_client):
    response = await async_client.post("/auth/login", json={
        "email": "nobody@example.com",
        "password": "testpassword123",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_me(async_client, test_user, auth_headers):
    response = await async_client.get("/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_get_me_unauthorized(async_client):
    response = await async_client.get("/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_me_invalid_token(async_client):
    response = await async_client.get("/auth/me", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401
