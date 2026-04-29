# The SecureLens AI Agent — How It Actually Works

This document explains the AI agent at the heart of SecureLens — what it does, how it thinks, and how all the pieces connect together.

---

## The Big Picture

SecureLens has two separate AI systems, and it's important to understand both:

1. **The Code Scanner Agent** — scans a GitHub repository for security vulnerabilities in your source code (OWASP Top 10, hardcoded secrets, broken access control, etc.)

2. **The Website Scanner AI** — scans a live URL for infrastructure-level security issues (missing headers, SSL misconfigs, exposed paths, etc.)

Both use Google Gemini as their AI engine. This document focuses primarily on the Code Scanner Agent because that's the more complex, agentic system. The website scanner AI is covered at the end.

---

## Part 1 — The Code Scanner Agent

### What Is It?

The Code Scanner Agent is a multi-step AI pipeline that mimics what a real penetration tester does when they look at a codebase.

A real AppSec engineer doesn't read every single file in your project. They look at the file list, immediately know which ones are interesting (auth routes, database models, API handlers), skip the boring stuff (tests, lock files, generated assets), then read those specific files carefully and report what they find.

That's exactly what this agent does. It runs in three phases:

```
GitHub Repo
     │
     ▼
┌─────────────────────────┐
│  Phase 1: TRIAGE        │  ← AI decides which files are worth reading
│  (1 API call)           │
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│  Phase 2: ANALYSIS      │  ← AI reads each file, finds vulnerabilities
│  (up to 5 API calls,    │
│   running in parallel)  │
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│  Phase 3: SUMMARY       │  ← AI writes an executive summary
│  (1 API call)           │
└─────────────────────────┘
     │
     ▼
┌─────────────────────────┐
│  Chat Interface         │  ← User asks follow-up questions
│  (1 API call per msg)   │
└─────────────────────────┘
```

---

### Phase 1 — Triage

**File:** `app/services/code_scanner/orchestrator.py` → `triage_files()`

The agent starts by fetching the complete file tree of the repository from the GitHub API. This gives us a flat list of every file in the repo — all paths, no content yet.

Then it sends that entire list to Gemini with a specific prompt that says: *"You are a Senior Application Security Engineer. From these files, pick the 5 most likely to contain security vulnerabilities. Return them as a JSON array."*

The AI looks at file paths like:
- `app/api/users/route.ts` — interesting, API route that probably handles user data
- `middleware.ts` — interesting, probably handles auth
- `lib/db.js` — interesting, probably has database queries
- `public/images/logo.png` — not interesting, just a static asset
- `package-lock.json` — not interesting, auto-generated

It returns a JSON object like:

```json
{
  "critical_files": [
    "app/api/users/route.ts",
    "middleware.ts",
    "lib/db.js",
    "app/users/page.js",
    "app/layout.tsx"
  ]
}
```

If the AI call fails for any reason (quota, network, etc.), the code falls back to just taking the first 5 files alphabetically. It never crashes — it degrades gracefully.

**Why this matters:** Without triage, you'd have to send every file to the AI for analysis. For a repo with 50 files, that's 50 API calls, 50x the cost, and 50x the chance of hitting rate limits. The triage step collapses that into 1 call, and the AI's reasoning is genuinely smarter than any file extension filter you could write by hand.

---

### Phase 2 — Concurrent File Analysis

**File:** `app/services/code_scanner/orchestrator.py` → `analyze_files()`

Once we have the list of 5 critical files, we fetch the actual source code for each one from GitHub, then send each file individually to Gemini for a deep security review.

The key technical detail here is **concurrency**. We don't do this one file at a time. All 5 files are analyzed at the same time, in parallel:

```python
results = await asyncio.gather(*(process_file(f) for f in triaged_files))
```

`asyncio.gather` fires off all 5 analysis tasks simultaneously and waits for all of them to finish. This means a 5-file scan takes roughly the same time as a 1-file scan — the bottleneck is the slowest individual file, not the sum of all of them.

To prevent flooding the API (which would cause 429 rate-limit errors), we wrap the actual API call in a `Semaphore`:

```python
semaphore = asyncio.Semaphore(5)

async with semaphore:
    response = await ai_client.aio.models.generate_content(...)
```

The Semaphore acts like a door with a maximum occupancy. Only 5 tasks can be inside at once. If more arrive, they wait at the door. This gives us parallel execution without overwhelming the API.

**Before fetching file content, we filter out junk:**

```python
if file_path.endswith('package-lock.json') or file_path.endswith('yarn.lock'):
    return []
```

Lock files can be 50,000+ lines long. Sending them to an AI is pointless — they're autogenerated by npm/yarn and contain no code that a developer wrote. We skip them immediately.

We also cap file content at 30,000 characters. If a file is longer than that, we truncate it. This prevents token limit errors on very large files.

**The prompt for each file looks like this:**

```
Review the following code from the file 'app/users/page.js' for security vulnerabilities.
Focus on OWASP Top 10: SQLi, XSS, Hardcoded Secrets, IDOR, Misconfigurations, etc.

CODE:
[file content here]

Return a JSON object with a key 'vulnerabilities' containing a list of objects.
Each object MUST have: severity, issue, explanation, suggested_fix, line_number.
```

The response comes back as structured JSON (we explicitly request `application/json` as the response MIME type so we don't have to strip markdown code fences), and we parse it directly into `VulnerabilityIssue` Pydantic models.

---

### Phase 3 — Executive Summary

**File:** `app/services/code_scanner/orchestrator.py` → `generate_summary()`

After all the vulnerabilities are collected, we send them all to Gemini one more time with a different prompt. This time we're asking it to act like a *Senior AppSec Manager* and write a 2-3 paragraph executive summary of the repository's overall security posture.

This is the text that goes in the `summary` field of the API response. It gives a human-readable overview before the detailed issue list.

If there are no vulnerabilities, this phase is skipped entirely and we return a hardcoded message.

---

### The Chat Interface

**File:** `app/routers/code_scan.py` → `chat_with_scan()`

After a scan completes, the results are saved to an in-memory dictionary (`scan_store`) keyed by the `scan_id`. This is a simple Python dict that lives in memory for as long as the server is running.

```python
scan_store: Dict[str, CodeScanResponse] = {}
```

When a user sends a chat message, they pass their `scan_id` along with it. The server looks up the full scan result, bundles it into a prompt, and sends it to Gemini:

```
You are SecureLens AI, an expert application security assistant.

Here is the context of the scan for the repository [repo_url]:
Summary: [executive summary]
Vulnerabilities: [full JSON list of vulnerabilities]

User Message: "Can you write a patch for the highest severity issue?"

Answer clearly and professionally. Provide code fixes if requested.
```

This means the AI is not having a generic conversation — it has the full context of what it actually found in the specific repository being discussed. It knows the file names, the exact vulnerability descriptions, and the suggested fixes. So when you ask "write me a patch", it writes a patch for the specific issue in the specific file it analysed, not generic example code.

**Important limitation:** The `scan_store` is in-memory only. If the server restarts, all scan contexts are lost. This is fine for development and demos. In a production system, you'd store this in the PostgreSQL database so chat sessions persist across deployments.

---

## Part 2 — The Website Scanner AI

**File:** `app/services/ai.py`

This is a separate, simpler AI layer that operates on the results of the infrastructure-level website scanner (the one that checks headers, SSL, cookies, etc.).

It has three functions:

### `enhance_security_issues()`

Takes the raw list of issues detected by the rule-based scanner and asks Gemini to enrich each one. The AI adds:
- A contextual severity rating (sometimes a "Medium" issue in a specific context is actually Critical)
- A plain-English, non-technical explanation a non-developer can understand
- A remediation code snippet (e.g. the exact Nginx config line to add a missing security header)

### `chat_with_scan_context()`

Same concept as the code scan chat, but for website scan results. The user can ask questions about their scan and get AI-powered answers grounded in the specific context of what was found.

### `generate_threat_narrative()`

This is the most creative AI function. Instead of listing issues individually, it asks Gemini to act like a red-teamer and write a "threat narrative" — a story of how an attacker might chain multiple vulnerabilities together to compromise the system.

For example, if a site has a missing `X-Frame-Options` header and also exposes its admin path, the AI might write: *"An attacker could combine the missing clickjacking protection with the exposed admin panel to lure a logged-in administrator into clicking a malicious link, granting the attacker admin access without ever needing credentials."*

This is significantly more actionable than a bullet list of independent issues.

---

## Prompt Engineering — Design Decisions

This section explains why each prompt was designed the way it is. Prompts are the most critical part of an AI agent — small changes in wording produce very different outputs.

---

### Triage Prompt

**Temperature: `0.1`** — Very low. We want the AI to make a deterministic, logical decision about which files are risky. We do not want creative or exploratory answers here. High temperature would cause the AI to sometimes pick random or irrelevant files.

**Response format: `application/json`** — We explicitly request JSON via the `response_mime_type` config parameter. Without this, Gemini wraps the JSON in a markdown code fence (` ```json ... ``` `), which breaks `json.loads()`. Forcing the MIME type eliminates all parsing overhead.

**Role: "Senior Application Security Engineer"** — Giving the model a specific professional role improves the quality of its file prioritisation. A generic prompt like "pick the most important files" produces weaker results than grounding the model in a specific domain expertise. It starts reasoning about auth routes and database queries rather than just file size or alphabetical order.

**Output key: `critical_files`** — We use a named key rather than a raw array so the response is unambiguous to parse. A raw array with no wrapper can be confused with other response formats.

---

### File Analysis Prompt

**Temperature: `0.2`** — Low but slightly higher than triage. Security analysis requires precise, grounded reasoning, but we give it a small amount of flexibility to reason across multiple vulnerability patterns in a single file. Too high (e.g. `0.7`) and the model starts inventing vulnerabilities that aren't there.

**OWASP Top 10 explicit list** — We enumerate specific vulnerability classes (SQLi, XSS, IDOR, Hardcoded Secrets, Misconfigurations) rather than saying "find security issues". Vague prompts produce vague results. Named categories anchor the model to established security standards and produce more consistent severity ratings across different files.

**Structured output schema enforced in the prompt** — We specify the exact keys each vulnerability object must have (`severity`, `issue`, `explanation`, `suggested_fix`, `line_number`). This is important because we parse the output directly into a Pydantic model. If the model returns different key names, parsing silently drops the data. By declaring the schema in plain English inside the prompt, we get consistent field names without needing to post-process the output.

**`line_number` as integer or null** — We explicitly allow null rather than requiring an integer, because some vulnerabilities are architectural (e.g. "no authentication on this endpoint") and don't have a single line to point to. A strict integer requirement would cause the model to hallucinate a line number.

**30,000 character cap** — The `gemini-2.0-flash` context window is large, but sending enormous files increases latency and cost significantly. Most security-critical logic in real files sits in the first few hundred lines. 30,000 characters (~6,000–8,000 lines) covers virtually all real source files while preventing edge cases from blowing up API response times.

**Lock file exclusion** — `package-lock.json` and `yarn.lock` are autogenerated by package managers and can be 50,000+ lines of JSON. They contain no developer-written logic. Sending them to the model wastes tokens and API quota, and the model occasionally returns false positives on dependency version strings (flagging outdated packages as vulnerabilities, which is technically true but unhelpful without context). We skip them with a hard filter before any API call is made.

---

### Summary Prompt

**Temperature: `0.4`** — Middle ground. The summary is a written paragraph, not structured data, so we want some natural language variation. But it's a professional security document, so we don't want it to be overly creative or inconsistent. `0.4` produces readable, varied prose that still stays factual and professional.

**Role: "Senior AppSec Manager"** — Different from the analysis role ("Senior Application Security Engineer"). The manager persona produces higher-level, prioritised language that talks about business risk rather than technical specifics. This is intentional — the summary is meant for someone reading quickly, not a developer who will fix the code.

---

### Chat Prompt

**Temperature: `0.5`** — Higher than the structured tasks because conversation requires natural, responsive language. The model needs to adapt its tone to the user's question — a technical "how does this work?" deserves a different register than "write me a patch".

**Full context injection** — We pass the entire scan result (repo URL, executive summary, full vulnerability JSON) into every chat message. We do not maintain a conversation history array. This is a deliberate tradeoff: a single large context is simpler to implement and avoids the complexity of managing a rolling message window, at the cost of slightly higher token usage per message. For a developer chat session (typically 2–5 messages), this is the right call.

**Role: "SecureLens AI"** — Giving the chat assistant a specific product name and identity ("You are SecureLens AI") improves response consistency and keeps the model on-topic. Without a defined persona, the model can drift into giving generic security advice unrelated to the specific scan results.

---

## The AI Client Setup

Both AI systems use the same `google-genai` SDK client. The client is initialised once at module load time:

```python
if settings.gemini_api_key:
    ai_client = genai.Client(api_key=settings.gemini_api_key)
else:
    ai_client = None
```

If no API key is set, `ai_client` is `None`, and every function that uses it has an early return that either returns empty results or a placeholder message. The app never crashes if the AI is unconfigured — it just degrades gracefully.

All API calls use the async interface (`client.aio.models.generate_content`) so they never block the FastAPI event loop.

---

## Model Selection

The current model used for all AI calls is **`gemini-2.0-flash`**.

The choice of model matters a lot for a system like this:

| Model | Speed | Quality | Free Tier Daily Limit |
|---|---|---|---|
| `gemini-2.5-flash` | Very fast | Excellent | ~20 requests (very low) |
| `gemini-2.0-flash` | Fast | Very good | 1,500 requests |
| `gemini-2.5-pro` | Slower | Best | Very low |

`gemini-2.0-flash` is the practical choice for a system doing concurrent file analysis. It's fast enough that concurrent scans complete in under a minute, good enough to catch real OWASP Top 10 issues, and has a high enough daily free limit for real usage.

To change the model, update the `model_name` attribute in `CodeScanOrchestrator.__init__()` and the hardcoded model string in the chat endpoint. Future versions of SecureLens will make this configurable via an environment variable, supporting any compatible LLM provider.

---

## Error Handling Philosophy

Every AI call in this system is wrapped in a `try/except` block. The system never lets an AI failure bubble up as a 500 error to the user if there's a reasonable fallback available.

- Triage fails → fall back to first 5 files alphabetically
- File analysis fails → skip that file, continue with others
- Summary generation fails → return a simple count ("Found N issues")
- Chat fails → return a user-friendly error message

The only place we raise an HTTP 500 is in the chat endpoint, because there's no meaningful fallback for a failed chat response — the user explicitly asked for an AI reply.
