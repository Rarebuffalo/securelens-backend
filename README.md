#  SecureLens AI — Backend

SecureLens AI Backend is the core security engine that powers the SecureLens AI agent. It performs live security analysis of applications and generates structured risk insights, issue explanations, and remediation guidance.

---

##  What This Backend Does

The SecureLens backend acts as the **security brain** of the system.

It:

- Scans live applications via URL
- Checks for security misconfigurations
- Detects common vulnerabilities (headers, exposure, HTTPS issues, etc.)
- Assigns a **security score**
- Categorizes risks into layers
- Generates **human-readable fix suggestions**

This backend is designed to evolve into an **AI-driven autonomous remediation agent**.

---

##  Security Layers Modeled

SecureLens structures vulnerabilities into logical layers:

| Layer               | Purpose                           |
| ------------------- | --------------------------------- |
| Transport Layer     | HTTPS, HSTS, secure communication |
| Server Config Layer | Security headers, CORS, policies  |
| Exposure Layer      | Sensitive endpoints, leaked paths |

---

## 🛠 Tech Stack

- **Python**
- **FastAPI**
- **HTTP analysis via Requests**
- JSON-based API output
- Designed for future AI integration

---

##  Installation

```bash
git clone https://github.com/Rarebuffalo/securelens-backend
cd securelens-backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

---

##  API Endpoint

### POST `/scan`

Scans an application URL.

**Request Body:**

```json
{
  "url": "https://example.com"
}
```

**Example Usage:**

```bash
curl -X POST "http://127.0.0.1:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://google.com"}'
```

## Future Roadmap

- AI agent for auto-remediation
- Codebase & deployment scanning
- Mobile app security checks
- CI/CD pipeline integration

---

##  License

This project is open-source and available under the **MIT License**. You are free to commit, contribute, and fork this repository.

Happy Hacking! 
