# SecureLens Onboarding and Setup Guide

This guide details how to set up the SecureLens development environment, run the FastAPI backend server, configure the database migrations, and install the local command-line interface (CLI).

---

## System Prerequisites

Ensure your development machine has the following tools installed:

* **Python:** Version 3.12 or higher.
* **Database:** PostgreSQL (for production) or SQLite (for local development).
* **Containerization (Optional):** Docker and Docker Compose (recommended for production deployment).

---

## Backend Server Setup

### 1. Local Environment Configuration

Clone the repository and initialize a Python virtual environment:

```bash
git clone https://github.com/Rarebuffalo/securelens-backend.git
cd securelens-backend
python -m venv venv
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

### 2. Environment Variables Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Open the newly created `.env` file and configure the settings. Below are the key configurations:

| Key | Default Value | Description |
|---|---|---|
| `APP_NAME` | SecureLens AI | Display name of the service |
| `DATABASE_URL` | sqlite+aiosqlite:///./securelens.db | Connection string (uses SQLite locally by default) |
| `GEMINI_API_KEY` | None | Google Gemini token (required for AI scans and chat) |
| `JWT_SECRET` | None | Secret string used for signing authentication tokens |

Note: If you want to use OpenAI or Anthropic models via the LiteLLM adapter, define `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in your environment.

### 3. Database Migrations

SecureLens uses Alembic to manage database schemas. Initialize and run migrations to create the database tables:

```bash
alembic upgrade head
```

This will run all SQL schema scripts and build your SQLite or PostgreSQL tables.

### 4. Running the Development Server

Start the FastAPI development server using Uvicorn:

```bash
uvicorn app.main:app --reload
```

The server will start at `http://127.0.0.1:8000`. You can access the interactive API docs at `http://127.0.0.1:8000/docs` to verify the installation.

### 5. Production Docker Deployment

To launch the full production stack containing the FastAPI app and a PostgreSQL database container:

```bash
docker compose up --build -d
```

This starts the containers in the background, maps port 8000 to the host, and persists database records using a Docker volume.

---

## CLI Client Installation

The `securelens` CLI allows you to execute scans directly from your local terminal and synchronize reports back to your backend account.

### 1. Automated Script Installation

You can install the CLI automatically using the provided installer:

```bash
chmod +x cli/install.sh
./cli/install.sh
```

Ensure you have activated your virtual environment before running the tool:

```bash
source venv/bin/activate
```

### 2. Manual Installation

Alternatively, you can install the CLI in editable mode manually:

```bash
pip install -e cli/
```

Verify that the CLI is installed and accessible:

```bash
securelens version
```

### 3. Connection and Model Configuration

Configure your CLI profile and connect it to your backend server:

```bash
securelens configure
```

This interactive wizard asks for:
* The backend server API URL (defaults to `http://127.0.0.1:8000`).
* Your preferred AI provider model (defaults to `gemini/gemini-2.0-flash`).
* Your API secret token.

These settings are written to `~/.securelens/config.yaml`.

---

## Verifying the Installation

To verify that the complete system is communicating correctly, run a mock scan using the CLI:

```bash
# Verify patterns scan and terminal output
securelens scan . --no-ai

# Verify connection to backend
securelens web https://example.com --no-ai
```
