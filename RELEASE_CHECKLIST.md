# SecureLens Release & Deployment Checklist

Use this checklist to verify production deployment readiness before and during public launch.

---

## Pre-Deployment Code & Security Verification

- [x] **Git repository clean:** No unexpected files or build artifacts tracked.
- [x] **No secrets committed:** Verified zero API keys, JWT secrets, or DB credentials in git history/diffs.
- [x] **`.env` properly ignored:** Verified in `.gitignore` and `.dockerignore`.
- [x] **108/108 Automated Tests passing:** Verified via `pytest -v` (100% pass rate).
- [x] **CLI installation verified:** Verified via `pip install -e cli/` and `pip install git+https://...#subdirectory=cli`.
- [x] **Offline CLI scan verified:** Verified `securelens scan --no-ai` works without network access or backend dependency.
- [x] **CLI local exporters verified:** Verified PDF, Markdown, and JSON report generation.
- [x] **Single-node architecture verified:** In-process scheduler and in-memory rate limiting boundaries understood.

---

## Production Environment & Secrets Checklist

- [ ] **Configure `JWT_SECRET`:** Generate a cryptographically secure random string:
  ```bash
  openssl rand -hex 32
  ```
- [ ] **Configure PostgreSQL Credentials:** Set a strong database password in `.env` for `POSTGRES_PASSWORD` and `DATABASE_URL`.
- [ ] **Configure `CORS_ORIGINS`:** Set to your authorized frontend domains (or leave empty if CLI/API only).
- [ ] **Configure Optional AI Provider:** Set `AI_MODEL` and `AI_API_KEY` in `.env` if enabling AI triage (or leave blank for offline-only mode).
- [ ] **Configure Optional Alerting:** Set `SLACK_WEBHOOK_URL` or `SMTP_*` variables if notifications are desired.

---

## Server Deployment Execution

- [ ] **Launch container stack:**
  ```bash
  docker compose up -d --build
  ```
- [ ] **Verify containers status:**
  ```bash
  docker compose ps
  # Both db and backend should report healthy / started
  ```
- [ ] **Verify health check:**
  ```bash
  curl -fsS http://localhost:8000/health
  # Response: {"status":"healthy","app":"SecureLens AI","version":"1.0.0"}
  ```
- [ ] **Verify Reverse Proxy & HTTPS:**
  - Nginx or Caddy configured to terminate TLS (port 443).
  - Reverse proxy forwards to `http://127.0.0.1:8000`.
  - PostgreSQL port remains private and unexposed.
- [ ] **Verify Database Backup Schedule:**
  - Automated cron job configured for periodic pg_dump:
  ```bash
  docker compose exec -T db pg_dump -U securelens securelens > /backups/securelens_$(date +%Y%m%d_%H%M%S).sql
  ```

---

## Free Demo Deployment (Render + Neon) Checklist

- [ ] **Neon database created:** Serverless PostgreSQL instance provisioned on [neon.tech](https://neon.tech).
- [ ] **Neon `DATABASE_URL` configured:** Connection string copied with SSL enabled.
- [ ] **Render Web Service created:** Python web service connected to GitHub repository on [render.com](https://render.com).
- [ ] **Render environment variables configured:** `DATABASE_URL`, `JWT_SECRET`, `CORS_ORIGINS`, `AI_MODEL`, `AI_API_KEY`.
- [ ] **Render build succeeds:** `pip install -r requirements.txt` builds cleanly.
- [ ] **Render service starts:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT` executes successfully.
- [ ] **`/health` returns 200:** Live public URL returns `{"status":"healthy","app":"SecureLens AI","version":"1.0.0"}`.
- [ ] **Authentication verified:** User registration and JWT issuance function against Neon DB.
- [ ] **Code scan sync verified:** `POST /code-scan/sync` saves records to Neon DB.
- [ ] **History verified:** `GET /code-scan/history` retrieves scans from Neon DB.
- [ ] **User isolation verified:** Multi-user tenant boundaries confirmed.
- [ ] **AI works if API key configured:** LiteLLM generates contextual issue analysis.
- [ ] **`--no-ai` behavior remains functional:** Deterministic pattern scanning operates without AI keys.
- [ ] **Nuclei status verified:** Gracefully skipped if binary absent on Render without breaking scans.
- [ ] **Public API URL verified:** Available for demo portfolios and CLI sync testing.

