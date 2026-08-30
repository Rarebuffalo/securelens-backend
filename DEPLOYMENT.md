# SecureLens Deployment Guide

This guide provides instructions for deploying a single-node SecureLens production instance using Docker Compose.

---

## Architecture & Product Model

SecureLens operates as a **CLI-first security tool** with an **optional hosted backend/API**:

* **Local / Offline CLI Mode:** The developer CLI (`securelens scan`) operates 100% locally on your machine. It does **not** require deploying, configuring, or connecting to any backend server.
* **Optional Hosted Backend:** Provides multi-user authentication, scan synchronization, centralized persistence, scan history, webhooks, scheduled recurring scans, and REST API integrations.

```
Internet / Developer CLI (Optional Sync)
               │
               ▼  (HTTPS Port 443)
┌────────────────────────────────────────────────────────┐
│     Reverse Proxy (Nginx / Caddy / Cloudflare TLS)     │
└──────────────────────────┬─────────────────────────────┘
                           │  (HTTP Proxy Pass)
                           ▼
┌────────────────────────────────────────────────────────┐
│                  FastAPI Application                   │
│         (Docker Container, Internal Port 8000)         │
└──────────────────────────┬─────────────────────────────┘
                           │  (Private Docker Network)
                           ▼
┌────────────────────────────────────────────────────────┐
│                 PostgreSQL 16 Database                 │
│         (Docker Container, Internal Port 5432)         │
└────────────────────────────────────────────────────────┘
```

---

## 1. System Requirements

* **Host Operating System:** Linux (Ubuntu 22.04+, Debian 12+, Arch Linux, RHEL 9+)
* **Container Runtime:** Docker Engine 24.0+ and Docker Compose v2.20+
* **Hardware Requirements:** 2 vCPUs, 4GB RAM minimum
* **Domain & TLS:** A registered domain name with an SSL/TLS terminating reverse proxy (e.g., Nginx, Caddy, Cloudflare)
* **Database:** PostgreSQL 16 (provisioned automatically via Docker Compose)
* **AI Provider (Optional):** API key for Google Gemini, OpenAI, Anthropic, or OpenRouter (or local Ollama)

---

## 2. Environment Variables

Create a `.env` file in the project root based on `.env.example`.

### Required Configuration

| Variable | Description |
|---|---|
| `DATABASE_URL` | Asynchronous PostgreSQL connection string. Set to `postgresql+asyncpg://securelens:<POSTGRES_PASSWORD>@db:5432/securelens` inside Docker. |
| `JWT_SECRET` | Secret key used for signing JWT bearer tokens. Generate with `openssl rand -hex 32`. |
| `CORS_ORIGINS` | Comma-separated list of allowed web frontend origins (e.g., `https://app.yourdomain.com`). |

### Optional Integrations

| Variable | Description | Default / Notes |
|---|---|---|
| `AI_MODEL` | LiteLLM model identifier | `gemini/gemini-2.0-flash` |
| `AI_API_KEY` | Provider API key for chosen LLM model | Blank (disables AI enhancement) |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for IP/domain reputation | Blank (skips lookup) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key for threat scoring | Blank (skips lookup) |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL for scan completion alerts | Blank (skips notification) |
| `SMTP_HOST` | SMTP server host for email notifications | Blank (skips email alerts) |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USERNAME` | SMTP username / sender address | Blank |
| `SMTP_PASSWORD` | SMTP application password | Blank |
| `SMTP_FROM_EMAIL` | Sender email address | Blank |
| `SMTP_USE_SSL` | Enable SSL for port 465 (`true`) or STARTTLS (`false`) | `false` |
| `NUCLEI_BINARY_PATH` | Explicit path to Nuclei binary for active scanning | Searches `$PATH` automatically |

---

## 3. First Deployment

1. Clone the repository to your production server:
   ```bash
   git clone https://github.com/Rarebuffalo/securelens-backend.git
   cd securelens-backend
   ```

2. Create and populate your production `.env` file:
   ```bash
   cp .env.example .env
   # Edit .env and set strong secrets
   nano .env
   ```

3. Build and launch the containerized stack:
   ```bash
   docker compose up -d --build
   ```

---

## 4. Health Check & Verification

Verify that both containers are running and healthy:

```bash
# Check container status
docker compose ps

# Test application health endpoint
curl -fsS http://localhost:8000/health
```

Expected response:
```json
{"status":"healthy","app":"SecureLens AI","version":"1.0.0"}
```

---

## 5. Operations & Maintenance

### Viewing Application Logs
```bash
# Stream live backend logs
docker compose logs -f backend

# Stream database logs
docker compose logs -f db
```

### Restarting the Services
```bash
docker compose restart
```

### Stopping the Services
```bash
docker compose down
```

### Database Backup
To perform an automated backup of the PostgreSQL database:
```bash
docker compose exec -T db pg_dump -U securelens securelens > "securelens_backup_$(date +%Y%m%d_%H%M%S).sql"
```

### Database Restore
To restore from a SQL backup file:
```bash
docker compose exec -T db psql -U securelens -d securelens < your_backup_file.sql
```

---

## 6. Reverse Proxy & HTTPS Configuration

Production internet traffic should terminate TLS at a reverse proxy (such as Nginx or Caddy) and forward requests to `http://127.0.0.1:8000`.

### Example Nginx Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 7. Architecture & Scaling Limitations

> [!WARNING]
> This deployment configuration is designed for a **single backend instance**. 
> The current in-process AsyncIO scheduler (`APScheduler`) and in-memory rate limiter (`SlowAPI`) are not designed for horizontally scaled replicas across multiple container nodes. For high-availability multi-node clustering, a shared Redis broker would be required.

---

## 8. AI Privacy Notice

* **Offline CLI Scanning:** Running `securelens scan --no-ai` executes 100% locally. Zero bytes of code or findings leave your machine.
* **AI-Enabled Scanning:** When AI analysis is enabled, matching code snippets and security findings are transmitted via HTTPS to the configured LLM provider (e.g., Google Gemini, OpenAI, Anthropic). For strict on-premises environments, configure `AI_MODEL=ollama/<model>` to run local LLMs.

---

## 9. Free Demo Deployment — Render + Neon

This section outlines how to deploy a 100% free demonstration instance of SecureLens backend using **Neon PostgreSQL** and **Render Free Web Service**.

```
GitHub Repository
       │
       ├── Render Free Web Service (FastAPI)
       │         │
       │         ▼
       └── Neon Free PostgreSQL (Serverless Database)
```

### Step 1: Create Neon Database
1. Go to [neon.tech](https://neon.tech) and create a free project.
2. Under **Dashboard**, copy your PostgreSQL connection string.
   - Example: `postgresql://user:password@ep-xyz.region.aws.neon.tech/neondb?sslmode=require`
   - *Note: SecureLens automatically normalizes `postgres://` or `postgresql://` to `postgresql+asyncpg://`.*

### Step 2: Create Render Web Service
1. Go to [render.com](https://render.com) and create a new **Web Service**.
2. Connect your GitHub repository (`Rarebuffalo/securelens-backend`).
3. Select **Python** runtime environment.
4. Set the build and start commands:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Configure Environment Variables in Render:
   - `DATABASE_URL`: Your copied Neon connection string
   - `JWT_SECRET`: A secure random string (generate via `openssl rand -hex 32`)
   - `CORS_ORIGINS`: Allowed frontend origins (e.g., `https://your-app.vercel.app` or leave blank for CLI-only)
   - `AI_MODEL`: `gemini/gemini-2.0-flash` (or another LiteLLM model)
   - `AI_API_KEY`: Your Gemini/OpenAI API key (optional)
6. Under **Advanced Settings**, set **Health Check Path** to `/health`.
7. Click **Create Web Service**.

### Step 3: Verify Public Endpoint
Once deployment completes, test the live health endpoint:
```bash
curl -fsS https://<your-render-service>.onrender.com/health
# Expected: {"status":"healthy","app":"SecureLens AI","version":"1.0.0"}
```

> [!NOTE]
> Render Free instances automatically spin down after 15 minutes of inactivity. The first request after idling may take 30–50 seconds to wake up the server. The in-process APScheduler operates while the service is active.
