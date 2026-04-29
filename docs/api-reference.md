# API Reference — SecureLens Backend

All endpoints run at `http://localhost:8000` in development.

Interactive documentation (Swagger UI) is available at `http://localhost:8000/docs`.

---

## Authentication

SecureLens uses JWT Bearer tokens for authentication. After registering or logging in, you get a token. Pass it in the `Authorization` header for any protected endpoint:

```
Authorization: Bearer <your_token>
```

Tokens are valid for 24 hours by default (configurable via `JWT_EXPIRY_MINUTES` in `.env`).

---

## Endpoints

### Health & Status

#### `GET /`
Returns a simple welcome message. Used to verify the server is up.

**Response:**
```json
{ "message": "SecureLens AI Backend is running" }
```

#### `GET /health`
Returns server health status and version info.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

### Authentication

#### `POST /auth/register`
Creates a new account and returns a JWT token immediately (no separate login needed).

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "myuser",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "token_type": "bearer"
}
```

**Errors:**
- `400` — Email or username already exists

---

#### `POST /auth/login`
Logs in with email and password, returns a JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:** Same as register.

**Errors:**
- `401` — Invalid credentials

---

#### `GET /auth/me`
Returns info about the currently authenticated user. Requires a valid token.

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "myuser",
  "created_at": "2026-04-25T10:00:00Z"
}
```

---

### Website Scanner

#### `POST /scan`
Scans a live URL for infrastructure-level security vulnerabilities. Authentication is optional — if you're logged in, the scan is saved to your history.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "score": 62,
  "grade": "C",
  "summary": "Found 8 security issues...",
  "issues": [
    {
      "layer": "Server Config",
      "issue": "Missing Content-Security-Policy header",
      "severity": "High",
      "explanation": "Without CSP, the browser cannot restrict...",
      "remediation_snippet": "add_header Content-Security-Policy \"default-src 'self'\";"
    }
  ],
  "threat_narrative": "An attacker could chain the missing CSP..."
}
```

The `score` is 0–100 (higher is better). The `grade` maps to:

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 50–74 | C |
| 25–49 | D |
| 0–24 | F |

**Errors:**
- `400` — Invalid URL or URL validation failed (SSRF protection)
- `422` — Malformed request body

---

### Scan History

All history endpoints require authentication.

#### `GET /scans`
Returns a list of all your past website scans.

**Response:**
```json
[
  {
    "id": "uuid",
    "url": "https://example.com",
    "score": 62,
    "grade": "C",
    "created_at": "2026-04-25T10:00:00Z"
  }
]
```

---

#### `GET /scans/{id}`
Returns the full details of a specific scan by ID.

---

#### `DELETE /scans/{id}`
Deletes a scan from your history.

**Response:** `204 No Content`

**Errors:**
- `404` — Scan not found or doesn't belong to your account

---

### Code Scanner (AI Agent)

These endpoints power the GitHub repository scanner.

#### `POST /code-scan/analyze`
Triggers the full AI agent pipeline against a GitHub repository. This is the main endpoint.

**What happens internally:**
1. Fetches the complete file tree from GitHub
2. AI selects the 5 most security-critical files (Triage)
3. AI analyzes each file concurrently for OWASP Top 10 issues (Analysis)
4. AI writes an executive summary (Summary)
5. Results are stored in memory under the returned `scan_id`

**Request Body:**
```json
{
  "repo_url": "https://github.com/username/repository",
  "github_token": "ghp_xxxxxxxxxxxx",
  "branch": "main"
}
```

- `repo_url` — Full GitHub repository URL
- `github_token` — A GitHub personal access token with `repo` read scope. Needed to access private repos and to avoid GitHub's anonymous rate limits.
- `branch` — Optional. Defaults to `"main"`.

**Response:**
```json
{
  "scan_id": "4432ad8e-4aa7-40bf-8f37-b0bbb96f6677",
  "repo_url": "https://github.com/username/repository",
  "summary": "The repository presents a moderate security risk...",
  "issues": [
    {
      "file_path": "app/users/page.js",
      "severity": "High",
      "issue": "Potential Broken Access Control on User List API",
      "explanation": "The client-side code fetches all users without authentication...",
      "suggested_fix": "Add auth middleware to the /users API endpoint...",
      "line_number": 12
    }
  ]
}
```

**Save the `scan_id`** — you need it to use the chat endpoint.

**Errors:**
- `500` — AI API error, GitHub API error, or invalid repo URL

---

#### `POST /code-scan/chat`
Opens a conversational interface with the AI, grounded in the context of a specific scan.

The AI knows exactly what vulnerabilities were found in which files. You can ask it to explain issues, write patches, prioritise fixes, or anything else security-related.

**Request Body:**
```json
{
  "scan_id": "4432ad8e-4aa7-40bf-8f37-b0bbb96f6677",
  "message": "Can you write a patch for the highest severity issue you found?"
}
```

**Response:**
```json
{
  "reply": "The highest severity issue was the Broken Access Control in app/users/page.js. Here's the fix...\n\n```javascript\n// Add this middleware to your API route\n..."
}
```

**Errors:**
- `404` — `scan_id` not found (scan expired or server restarted)
- `500` — AI API error

**Note:** Scan contexts are stored in memory and are lost when the server restarts. Always run a fresh `/code-scan/analyze` first when starting a new session.

---

#### `GET /code-scan/models`
Lists all Gemini models available to your API key. Useful for debugging model access issues.

**Response:**
```json
{
  "models": [
    "models/gemini-2.0-flash",
    "models/gemini-2.5-flash",
    "models/gemini-2.5-pro"
  ]
}
```

---

## Rate Limits

The API is rate-limited to **30 requests per minute** by default (configurable via `RATE_LIMIT` in `.env`).

The Gemini AI calls are additionally subject to Google's API rate limits:

| Model | Free Tier RPM | Free Tier RPD |
|---|---|---|
| `gemini-2.0-flash` | 15 | 1,500 |
| `gemini-2.5-flash` | 10 | ~20 |

If you hit the Gemini rate limit, the API returns a `429` from Google which surfaces as a `500` from the SecureLens server. Wait 60 seconds and try again.

---

## Error Codes

| Code | Meaning |
|---|---|
| `400` | Bad request — check your input |
| `401` | Not authenticated — missing or expired token |
| `403` | Forbidden — you don't have permission for this resource |
| `404` | Resource not found |
| `422` | Validation error — malformed request body |
| `429` | Rate limited — slow down your requests |
| `500` | Server error — usually an AI API failure |
