# SecureLens AI — Backend

SecureLens AI Backend is the core security engine that powers the SecureLens AI agent. It performs live security analysis of applications and generates structured risk insights, issue explanations, and remediation guidance.

---

## What This Backend Does

The SecureLens backend acts as the **security brain** of the system.

It:

- Scans live applications via URL
- Checks for security misconfigurations
- Detects common vulnerabilities (headers, exposure, HTTPS issues, etc.)
- Assigns a **security score**
- Categorizes risks into layers
- Generates **human-readable fix suggestions**
- Validates URLs and prevents SSRF attacks
- Rate limits API requests
- **User authentication** with JWT tokens
- **Scan history** — saves and retrieves past scan results

This backend is designed to evolve into an **AI-driven autonomous remediation agent**.

---

## Security Layers Modeled

SecureLens structures vulnerabilities into 5 logical layers with **30+ security checks**:

| Layer               | Checks | Purpose                                        |
| ------------------- | ------ | ---------------------------------------------- |
| Transport Layer     | 6      | HTTPS, HSTS analysis, mixed content prevention |
| SSL/TLS Layer       | 5      | Certificate expiry, TLS version, chain issues  |
| Server Config Layer | 14     | Security headers, CSP analysis, info disclosure|
| Cookie Security     | 4      | HttpOnly, Secure, SameSite flags               |
| Exposure Layer      | 25+    | Sensitive paths, robots.txt, directory listing  |

---

## Tech Stack

- **Python 3.12+**
- **FastAPI** — async web framework
- **httpx** — async HTTP client
- **SQLAlchemy 2.0** — async ORM (SQLite dev / PostgreSQL production)
- **Pydantic v2** — data validation & settings
- **python-jose** — JWT authentication
- **passlib + bcrypt** — password hashing
- **SlowAPI** — rate limiting
- **Docker** — containerized deployment
- **pytest** — testing

---

## Project Structure

```
securelens-backend/
├── app/
│   ├── main.py                 # FastAPI app + middleware + lifespan
│   ├── config.py               # Pydantic settings (.env)
│   ├── database.py             # Async SQLAlchemy engine & session
│   ├── models/
│   │   ├── user.py             # User ORM model
│   │   └── scan.py             # ScanResult ORM model
│   ├── schemas/
│   │   ├── auth.py             # Auth request/response models
│   │   └── scan.py             # Scan request/response models
│   ├── routers/
│   │   ├── auth.py             # Register, login, me
│   │   ├── health.py           # Health check endpoints
│   │   ├── scan.py             # Scan endpoint
│   │   └── history.py          # Scan history endpoints
│   ├── services/
│   │   ├── scoring.py          # Scoring engine
│   │   └── scanner/
│   │       ├── base.py         # Abstract scanner interface
│   │       ├── transport.py    # Transport & HSTS checks
│   │       ├── ssl_checker.py  # SSL/TLS certificate analysis
│   │       ├── headers.py      # Header security checks
│   │       ├── cookies.py      # Cookie security checks
│   │       └── exposure.py     # Sensitive path detection
│   ├── middleware/
│   │   ├── auth.py             # JWT auth dependencies
│   │   └── rate_limiter.py     # SlowAPI rate limiting
│   └── utils/
│       ├── auth.py             # JWT & password utilities
│       └── validators.py       # URL validation & SSRF prevention
├── tests/
│   ├── conftest.py             # Test fixtures (in-memory DB)
│   ├── test_auth.py
│   ├── test_health.py
│   ├── test_scan.py
│   ├── test_history.py
│   ├── test_validators.py
│   ├── test_transport.py
│   ├── test_headers.py
│   ├── test_ssl_checker.py
│   ├── test_cookies.py
│   └── test_scoring.py
├── main.py                     # Root entry point (backward compat)
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Installation

### Local Development (SQLite)

```bash
git clone https://github.com/Rarebuffalo/securelens-backend
cd securelens-backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

The database is auto-created as `securelens.db` on first run.

### Docker (with PostgreSQL)

```bash
cp .env.example .env
docker compose up --build
```

---

## Configuration

Copy `.env.example` to `.env` and customize:

| Variable              | Default                                    | Description                       |
| --------------------- | ------------------------------------------ | --------------------------------- |
| `APP_NAME`            | SecureLens AI                              | Application name                  |
| `APP_VERSION`         | 1.0.0                                      | Application version               |
| `DEBUG`               | true                                       | Enable debug mode & docs          |
| `HOST`                | 0.0.0.0                                    | Server host                       |
| `PORT`                | 8000                                       | Server port                       |
| `CORS_ORIGINS`        | http://localhost:3000,http://localhost:5173 | Allowed CORS origins              |
| `RATE_LIMIT`          | 30/minute                                  | API rate limit                    |
| `SCAN_TIMEOUT`        | 5                                          | HTTP request timeout (seconds)    |
| `PATH_CHECK_TIMEOUT`  | 3                                          | Sensitive path check timeout (s)  |
| `DATABASE_URL`        | sqlite+aiosqlite:///./securelens.db        | Database connection string        |
| `JWT_SECRET`          | (change in production!)                    | Secret key for JWT signing        |
| `JWT_ALGORITHM`       | HS256                                      | JWT signing algorithm             |
| `JWT_EXPIRY_MINUTES`  | 1440                                       | Token expiry (default: 24h)       |

---

## API Endpoints

### Health

| Method | Endpoint   | Description      |
| ------ | ---------- | ---------------- |
| GET    | `/`        | Welcome message  |
| GET    | `/health`  | App status       |

### Authentication

| Method | Endpoint          | Description               | Auth |
| ------ | ----------------- | ------------------------- | ---- |
| POST   | `/auth/register`  | Create account + get token| No   |
| POST   | `/auth/login`     | Login + get token         | No   |
| GET    | `/auth/me`        | Get current user info     | Yes  |

### Scanning

| Method | Endpoint         | Description                          | Auth     |
| ------ | ---------------- | ------------------------------------ | -------- |
| POST   | `/scan`          | Scan a URL (saves if authenticated)  | Optional |

### Scan History

| Method | Endpoint          | Description               | Auth |
| ------ | ----------------- | ------------------------- | ---- |
| GET    | `/scans`          | List your scan history    | Yes  |
| GET    | `/scans/{id}`     | Get scan details by ID    | Yes  |
| DELETE | `/scans/{id}`     | Delete a scan             | Yes  |

### Example Usage

**Register:**
```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "username": "myuser", "password": "securepass123"}'
```

**Scan (authenticated):**
```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"url": "https://google.com"}'
```

**View scan history:**
```bash
curl http://127.0.0.1:8000/scans \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Running Tests

```bash
pytest tests/ -v
```

Tests use an in-memory SQLite database — no external DB needed.

---

## Future Roadmap

- AI agent for auto-remediation
- PDF report generation
- CI/CD pipeline integration
- DNS security checks (SPF, DKIM, DMARC)
- Technology fingerprinting
- JavaScript library CVE detection

---

## License

This project is open-source and available under the **MIT License**.

Happy Hacking! 🛡️
