# SecureLens API Documentation (Frontend Integration Guide)

This document is designed to act as the primary blueprint for the `securelens-frontend` application. It details exactly how the frontend should communicate with the backend.

**Base URL**: `http://localhost:8000`

---

## 1. Authentication
SecureLens uses JWT Bearer tokens for UI authentication and API Keys for programmatic CI/CD usage. The frontend will rely exclusively on JWTs.

### `POST /auth/register`
- **Payload**: `{"email": "user@example.com", "username": "user", "password": "securepassword"}`
- **Response**: `{"id": "uuid", "email": "user@example.com", "username": "user"}`

### `POST /auth/login`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Payload**: `username=user@example.com&password=securepassword`
- **Response**: `{"access_token": "ey...", "token_type": "bearer"}`
- **Action**: Store `access_token` in `localStorage` or secure cookie. Attach it as `Authorization: Bearer <token>` to all subsequent requests.

---

## 2. Dashboard Analytics
Used for populating the home page charts and historical views.

### `GET /scans/trends`
- **Auth Required**: Yes
- **Response**:
```json
{
  "total_scans": 12,
  "average_score": 85,
  "history": [
    {"url": "https://example.com", "score": 90, "date": "2023-10-27T..."},
    {"url": "https://staging.com", "score": 45, "date": "2023-10-26T..."}
  ]
}
```

---

## 3. The Scanning Engine
The core functionality of the product.

### `POST /scans/scan`
- **Auth Required**: Optional (If authenticated, saves to DB. If anonymous, returns ephemeral result).
- **Payload**: `{"url": "https://example.com"}`
- **Response**:
```json
{
  "id": "abc-123",
  "url": "https://example.com",
  "security_score": 85,
  "layers": {
    "Network": "Safe",
    "Headers": "Warning"
  },
  "issues": [
    {
      "issue": "Missing HTTPOnly on Session",
      "severity": "Critical",
      "layer": "Cookies",
      "fix": "Set HttpOnly flag to true",
      "contextual_severity": "High",
      "explanation": "Because you are using React, XSS could lead to cookie theft...",
      "remediation_snippet": "res.cookie('token', token, { httpOnly: true })"
    }
  ],
  "created_at": "2023-10-27T..."
}
```

---

## 4. AI Interfacing & Diagnostics
Views that trigger LLM behavior based on previous scans.

### `POST /scans/{scan_id}/chat`
- **Payload**: `{"message": "How do I fix the missing SPF record in AWS Route53?"}`
- **Response**: `{"reply": "To fix this in AWS..."}`

### `GET /scans/{scan_id}/threat-narrative`
- **Response**: `{"narrative": "An attacker could chain your missing CSP header with your exposed Git directory to..."}`

### `GET /scans/{old_id}/diff/{new_id}`
- **Response**: Returns lists of `resolved_issues`, `new_issues`, `persisting_issues`, and the integer `score_change`.

---

## 5. Webhooks & Exports
Settings and CI/CD generation views.

- **`GET /scans/{scan_id}/export/pdf`**: Triggers a browser file download of the PDF report.
- **`GET /scans/{scan_id}/export/csv`**: Triggers a CSV download.
- **`POST /webhooks`**: `{"target_url": "https://my-discord.com/hook"}`
- **`GET /webhooks`**: Returns a list of active webhooks for the user.
- **`DELETE /webhooks/{webhook_id}`**: Revokes a webhook.
