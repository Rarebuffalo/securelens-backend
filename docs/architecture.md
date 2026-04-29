# Architecture Overview

This document explains how the different pieces of SecureLens fit together — what each layer does, why it exists, and how data flows through the system.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENT                                │
│  (Next.js Frontend / Swagger UI / curl / API consumer)       │
└───────────────────────────────┬──────────────────────────────┘
                                │  HTTP requests
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                    FASTAPI APPLICATION                       │
│                                                              │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐   │
│  │  Auth Router  │  │  Scan Router  │  │ Code Scan Router│   │
│  │  /auth/*      │  │  /scan        │  │  /code-scan/*   │   │
│  └───────┬───────┘  └───────┬───────┘  └────────┬────────┘   │
│          │                  │                    │           │
│          ▼                  ▼                    ▼           │
│  ┌──────────────┐  ┌─────────────────┐  ┌──────────────┐     │
│  │ Auth Service │  │ Scanner Service │  │  Orchestrator│     │
│  │ JWT + Users  │  │ 5 check layers  │  │ 3-phase agent│     │
│  └──────┬───────┘  └───────┬─────────┘  └──────┬───────┘     │
│         │                  │                    │            │
└─────────┼──────────────────┼────────────────────┼────────────┘
          │                  │                    │
          ▼                  ▼                    ▼
   ┌─────────────┐   ┌──────────────┐    ┌──────────────┐
   │ PostgreSQL  │   │ Target URLs  │    │  GitHub API  │
   │  Database   │   │ (live scans) │    │  + Gemini AI │
   └─────────────┘   └──────────────┘    └──────────────┘
```

---

## Application Layers

### 1. FastAPI Application (`app/main.py`)

This is the entry point. It creates the FastAPI app, registers all the routers, sets up CORS, and configures the lifespan (startup/shutdown logic like creating database tables).

FastAPI is async from top to bottom. Every request handler is an `async def` function, which means the server can handle many concurrent requests without blocking on I/O — critical for a system that makes lots of external HTTP calls.

The app listens on port `8000` and serves:
- A REST API for all functionality
- An interactive Swagger UI at `/docs`
- An OpenAPI schema at `/openapi.json`

---

### 2. Routers (`app/routers/`)

Routers are just groups of related endpoints. FastAPI uses them to keep the codebase organised.

| File | What It Handles |
|---|---|
| `auth.py` | Register, login, get current user |
| `scan.py` | Website URL scanning |
| `history.py` | Reading and deleting past scan results |
| `code_scan.py` | GitHub repo scanning + AI chat |
| `health.py` | Health check endpoints |

Routers don't contain business logic. They receive the request, call the appropriate service, and return the result. They're thin by design.

---

### 3. Services (`app/services/`)

Services contain the actual business logic.

#### `scanner/` — The Website Scanner

A collection of five independent checkers, each responsible for one "layer" of security:

- `transport.py` — Checks if the site uses HTTPS and implements HSTS correctly
- `ssl_checker.py` — Validates the SSL certificate (expiry, chain, TLS version)
- `headers.py` — Checks for the presence and correct configuration of security headers (CSP, X-Frame-Options, etc.)
- `cookies.py` — Checks session cookies for HttpOnly, Secure, and SameSite flags
- `exposure.py` — Probes for exposed sensitive paths like `/admin`, `/.env`, `/phpinfo.php`

Each checker runs independently. The scan router calls all of them, collects their results, passes them to the scoring engine, then sends everything through the AI service for enhancement.

#### `code_scanner/` — The Code Scanner Agent

Contains the three-phase AI pipeline. See [ai-agent.md](./ai-agent.md) for a full explanation.

- `orchestrator.py` — The main pipeline class (Triage → Analysis → Summary)
- `github_client.py` — Handles all GitHub API communication

#### `ai.py` — Website Scanner AI Layer

Standalone functions that use Gemini to enhance the website scanner's results: `enhance_security_issues()`, `chat_with_scan_context()`, `generate_threat_narrative()`.

#### `scoring.py` — The Scoring Engine

A pure Python function that takes the list of issues from all scanners, applies weights based on severity, and produces a 0–100 score and an A–F letter grade. No AI involved here — it's deterministic and consistent.

---

### 4. Schemas (`app/schemas/`)

Pydantic models that define the shape of every request and response. FastAPI uses these for automatic validation, serialisation, and documentation generation.

If a request body doesn't match the schema, FastAPI returns a `422` automatically without your handler even being called.

Key schemas:

- `auth.py` — `RegisterRequest`, `LoginRequest`, `TokenResponse`, `UserResponse`
- `scan.py` — `ScanRequest`, `ScanResponse`, `IssueDetail`
- `code_scan.py` — `CodeScanRequest`, `CodeScanResponse`, `VulnerabilityIssue`, `CodeChatRequest`, `CodeChatResponse`

---

### 5. Models (`app/models/`)

SQLAlchemy ORM models — the Python representation of database tables.

- `user.py` — The `User` table (id, email, username, hashed_password, created_at)
- `scan.py` — The `ScanResult` table (id, user_id, url, score, grade, full result JSON)

These are what get stored in PostgreSQL. The code scanner's results are *not* stored in the database in the current version — they're kept in an in-memory dict in `code_scan.py`.

---

### 6. Middleware (`app/middleware/`)

- `auth.py` — The `get_current_user` dependency. Any endpoint that requires authentication uses this. It validates the JWT token from the `Authorization` header and returns the user object.
- `rate_limiter.py` — SlowAPI configuration. Limits the number of requests per IP per minute.

---

### 7. Utils (`app/utils/`)

- `auth.py` — Low-level JWT functions: creating tokens, verifying tokens, hashing passwords, checking passwords
- `validators.py` — URL validation and SSRF protection. Before scanning any URL, we check it's not a private IP address or localhost, which would let attackers use our scanner to probe internal networks

---

## Data Flow — Code Scan Request

This is exactly what happens when you call `POST /code-scan/analyze`:

```
1. Request arrives at FastAPI
      │
2. Pydantic validates the body → CodeScanRequest(repo_url, github_token, branch)
      │
3. Router creates a CodeScanOrchestrator instance
      │
4. GitHubClient.get_repo_tree() → fetches all file paths via GitHub Trees API
      │
      ├── Makes 1-2 GitHub API calls (uses token for auth)
      └── Returns: ["app/page.js", "app/users/page.js", "package.json", ...]
      │
5. orchestrator.triage_files() → sends file list to Gemini
      │
      ├── 1 Gemini API call with all filenames
      └── Returns: ["app/users/page.js", "middleware.ts", ...] (5 files)
      │
6. orchestrator.analyze_files() → fetches and scans each file
      │
      ├── GitHubClient.get_file_content() × 5 (concurrent, async)
      ├── Gemini generate_content() × 5 (concurrent, async, behind Semaphore)
      └── Returns: [VulnerabilityIssue, VulnerabilityIssue, ...]
      │
7. orchestrator.generate_summary() → writes executive summary
      │
      ├── 1 Gemini API call with all vulnerability data
      └── Returns: "The repository presents a moderate risk..."
      │
8. Router creates CodeScanResponse with a UUID scan_id
      │
9. scan_store[scan_id] = response  (saved in-memory for chat)
      │
10. Response returned to client (JSON)
```

Total external API calls: 2-3 GitHub + 7 Gemini = ~9-10 calls per scan.

---

## Database

We use PostgreSQL in production (via Docker Compose) and SQLite in local development.

The connection is managed by SQLAlchemy's async engine. All database operations use `async with get_db() as session:` — they never block.

Migrations are managed by Alembic. To run migrations:

```bash
alembic upgrade head
```

The tables are also auto-created on startup in development mode (the `create_all()` call in `main.py`'s lifespan function).

---

## Environment Configuration

All configuration is driven by the `.env` file. The `config.py` file uses Pydantic's `BaseSettings` to read it:

```python
class Settings(BaseSettings):
    gemini_api_key: str | None = None
    database_url: str = "sqlite+aiosqlite:///./securelens.db"
    jwt_secret: str = "change-me-in-production"
    # ...
```

If a required variable is missing, Pydantic raises an error on startup — not silently at runtime.

See `.env.example` for the full list of options, or the Configuration section in [README.md](../README.md).

---

## Docker Setup

The `docker-compose.yml` runs two services:

```
backend   ← FastAPI app (port 8000)
db        ← PostgreSQL (port 5432, internal only)
```

The backend container reads `DATABASE_URL` from `.env` and connects to the `db` container over the internal Docker network. PostgreSQL data persists in a Docker volume across restarts.

To rebuild from scratch:

```bash
docker compose down -v   # removes containers AND the data volume
docker compose up --build
```
