from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str


@app.get("/")
def read_root():
    return {"message": "SecureLens AI backend running 🚀"}


@app.post("/scan")
def scan_website(data: ScanRequest):
    url = data.url
    issues = []
    score = 100

    layers = {
        "Transport Layer": {"issues": 0, "status": "green"},
        "Server Config Layer": {"issues": 0, "status": "green"},
        "Exposure Layer": {"issues": 0, "status": "green"}
    }

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Transport Layer
        if not url.startswith("https"):
            issues.append({
                "issue": "Website is not using HTTPS",
                "severity": "Critical",
                "layer": "Transport Layer",
                "fix": "Install SSL certificate and redirect HTTP to HTTPS"
            })
            score -= 15
            layers["Transport Layer"]["issues"] += 1

        # Server Config
        if "Content-Security-Policy" not in headers:
            issues.append({
                "issue": "Missing Content-Security-Policy header",
                "severity": "Warning",
                "layer": "Server Config Layer",
                "fix": "Add header: Content-Security-Policy: default-src 'self';"
            })
            score -= 5
            layers["Server Config Layer"]["issues"] += 1

        if "X-Frame-Options" not in headers:
            issues.append({
                "issue": "Missing X-Frame-Options header",
                "severity": "Warning",
                "layer": "Server Config Layer",
                "fix": "Add header: X-Frame-Options: SAMEORIGIN"
            })
            score -= 5
            layers["Server Config Layer"]["issues"] += 1

        if "Strict-Transport-Security" not in headers:
            issues.append({
                "issue": "Missing HSTS header",
                "severity": "Warning",
                "layer": "Server Config Layer",
                "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            })
            score -= 5
            layers["Server Config Layer"]["issues"] += 1

        if headers.get("Access-Control-Allow-Origin") == "*":
            issues.append({
                "issue": "CORS allows all origins (*)",
                "severity": "Warning",
                "layer": "Server Config Layer",
                "fix": "Restrict Access-Control-Allow-Origin to trusted domains"
            })
            score -= 5
            layers["Server Config Layer"]["issues"] += 1

        # Exposure
        sensitive_paths = ["/admin", "/.env", "/backup", "/debug"]

        for path in sensitive_paths:
            try:
                test_url = url.rstrip("/") + path
                r = requests.get(test_url, timeout=3)
                if r.status_code == 200:
                    issues.append({
                        "issue": f"Sensitive path exposed: {path}",
                        "severity": "Critical",
                        "layer": "Exposure Layer",
                        "fix": f"Restrict access to {path} using authentication or firewall rules"
                    })
                    score -= 15
                    layers["Exposure Layer"]["issues"] += 1
            except:
                pass

    except Exception as e:
        return {"error": str(e)}

    # Set layer status
    for layer in layers:
        count = layers[layer]["issues"]
        if count == 0:
            layers[layer]["status"] = "green"
        elif count < 3:
            layers[layer]["status"] = "yellow"
        else:
            layers[layer]["status"] = "red"

    return {
        "url": url,
        "security_score": max(score, 0),
        "layers": layers,
        "issues": issues
    }
