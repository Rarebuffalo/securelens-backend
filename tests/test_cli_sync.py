import pytest

@pytest.mark.asyncio
async def test_sync_codebase_scan_anonymous(async_client):
    payload = {
        "repo_url": "test-repo",
        "summary": "This is a test summary",
        "issues": [
            {
                "file_path": "auth.py",
                "severity": "High",
                "issue": "SQL Injection",
                "explanation": "Dynamic query in sql statement",
                "suggested_fix": "Use parameters",
                "line_number": 10
            }
        ]
    }
    response = await async_client.post("/code-scan/sync", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] is not None
    assert data["repo_url"] == "test-repo"
    assert data["summary"] == "This is a test summary"
    assert len(data["issues"]) == 1
    assert data["issues"][0]["issue"] == "SQL Injection"

@pytest.mark.asyncio
async def test_sync_codebase_scan_authenticated(async_client, test_user, auth_headers):
    payload = {
        "repo_url": "my-secure-repo",
        "summary": "Everything is secure",
        "issues": []
    }
    response = await async_client.post("/code-scan/sync", json=payload, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] is not None
    assert data["repo_url"] == "my-secure-repo"
    assert len(data["issues"]) == 0
