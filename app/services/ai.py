"""
AI Service Layer — Provider-Agnostic via LiteLLM
==================================================

Why LiteLLM?
  Previously every AI call used the google-genai SDK directly, which meant
  the entire codebase was hard-wired to Gemini. Switching to OpenAI or
  Claude would require rewriting every file that touched AI.

  LiteLLM is a thin translation layer. You call one function, it handles
  the right SDK under the hood based on the model string you pass:
    - "gpt-4o-mini"                  → OpenAI
    - "claude-3-5-haiku-20241022"    → Anthropic
    - "gemini/gemini-2.0-flash"      → Google Gemini
    - "ollama/llama3.1"              → local Ollama instance
    - "openrouter/..."               → OpenRouter

  Now you only need to change two env vars (AI_MODEL, AI_API_KEY) to switch
  providers — no code changes required.

Public API (used by the rest of the app):
  call_ai(prompt, temperature, json_mode)  → str
  enhance_security_issues(issues)           → dict
  chat_with_scan_context(...)              → str
  generate_threat_narrative(context_data)  → str
"""

import json
import logging
from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core LiteLLM wrapper
# ---------------------------------------------------------------------------

async def call_ai(
    prompt: str,
    temperature: float = 0.3,
    json_mode: bool = False,
) -> str:
    """
    The single entry-point for all AI calls in SecureLens.

    Parameters
    ----------
    prompt      : The full prompt string to send to the model.
    temperature : Creativity level (0 = deterministic, 1 = creative).
    json_mode   : If True, instruct the model to return valid JSON only.
                  This maps to response_format={"type":"json_object"} on
                  providers that support it (OpenAI, Gemini via LiteLLM).

    Returns
    -------
    The model's text response as a plain string. Empty string on failure.
    """
    import litellm

    api_key = settings.effective_ai_key
    model = settings.ai_model

    if not api_key and not model.startswith("ollama/"):
        logger.warning("No AI API key configured. Skipping AI call.")
        return ""

    messages = [{"role": "user", "content": prompt}]

    kwargs: dict = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "api_key": api_key,
    }

    # JSON mode: supported natively by OpenAI and LiteLLM proxied Gemini.
    # For providers that don't support it, LiteLLM silently ignores the flag.
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    try:
        response = await litellm.acompletion(**kwargs)
        return response.choices[0].message.content or ""
    except Exception as e:
        logger.error(f"LiteLLM call failed [model={model}]: {e}")
        return ""


# ---------------------------------------------------------------------------
# Domain-specific AI functions
# ---------------------------------------------------------------------------

async def enhance_security_issues(issues: list[dict]) -> dict:
    """
    Takes a raw list of scanner-detected issues and enriches each one with:
      - contextual_severity : AI-assessed severity in the real-world context
      - explanation         : Plain-English description of the risk
      - remediation_snippet : Concrete code or config fix

    Returns a dict {"enhanced_issues": [...]} that mirrors the original list
    with the three new fields merged in.
    """
    if not settings.effective_ai_key:
        logger.warning("AI enhancements skipped — no AI API key set.")
        return {"enhanced_issues": issues}

    prompt = (
        "You are a senior cybersecurity automation agent. Always respond with valid JSON.\n"
        "Analyze the following security vulnerabilities:\n"
        f"{json.dumps(issues, indent=2)}\n\n"
        "Return a JSON object with a single key 'enhanced_issues' containing a list of objects. "
        "Each object MUST correspond to one of the original issues and have the following keys: "
        "'issue' (exact string of the original issue), "
        "'contextual_severity' (Low, Medium, High, or Critical), "
        "'explanation' (a 1-2 sentence non-technical explanation of the real risk), "
        "'remediation_snippet' (an actionable code snippet or config fix, or 'N/A')."
    )

    raw = await call_ai(prompt, temperature=0.2, json_mode=True)
    if not raw:
        return {"enhanced_issues": issues, "ai_error": "Empty response from AI"}

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI JSON response: {e}\nRaw: {raw[:500]}")
        return {"enhanced_issues": issues, "ai_error": "JSON parse error"}


async def chat_with_scan_context(scan_id: str, context_data: dict, user_message: str) -> str:
    """
    Powers the conversational chat feature for web scans.

    The full scan context (score, layers, issues) is injected into the prompt
    so the model can answer specific questions about the scan results.
    """
    if not settings.effective_ai_key:
        return "AI Chat is disabled because no AI API key is configured."

    prompt = (
        "You are SecureLens AI, an expert cybersecurity assistant. "
        "You are helping a developer understand a security scan report for their website. "
        f"Here is the context of the scan:\n{json.dumps(context_data, indent=2)}\n\n"
        f"Developer's question: {user_message}\n\n"
        "Answer clearly and professionally. Reference specific findings from the scan when relevant."
    )

    result = await call_ai(prompt, temperature=0.5)
    return result or "I couldn't generate a response. Please try again."


async def generate_threat_narrative(context_data: dict) -> str:
    """
    Generates a 2-3 paragraph red-team style threat narrative.

    Explains how an attacker could chain the discovered vulnerabilities
    together to compromise the system. Used in the PDF report.
    """
    if not settings.effective_ai_key:
        return "AI Threat Narrative is disabled because no AI API key is configured."

    prompt = (
        "You are a senior cybersecurity red-teamer. Analyze the following security scan results "
        "and weave them into a single, cohesive 'Threat Narrative'. Explain how an attacker might "
        "chain these specific vulnerabilities together to compromise the system. "
        "Keep it professional, concise (2-3 paragraphs), and actionable.\n\n"
        f"Scan Context:\n{json.dumps(context_data, indent=2)}"
    )

    result = await call_ai(prompt, temperature=0.7)
    return result or "Could not generate threat narrative."


async def generate_diff_narrative(diff_data: dict) -> str:
    """
    Generates a plain-English summary of the changes between two scans.

    Given the resolved, new, and persisting issues plus the score change,
    the model writes a short paragraph explaining what improved, what
    regressed, and what still needs attention — written for a developer
    who wants to understand progress at a glance.
    """
    if not settings.effective_ai_key:
        return "AI narration is disabled because no AI API key is configured."

    score_change = diff_data.get("score_change", 0)
    resolved = diff_data.get("resolved_issues", [])
    new_issues = diff_data.get("new_issues", [])
    persisting = diff_data.get("persisting_issues", [])

    prompt = (
        "You are SecureLens AI, a cybersecurity assistant. "
        "A developer has run two security scans on the same URL at different points in time. "
        "Here is the comparison between the two scans:\n\n"
        f"Score change: {score_change:+d} points\n"
        f"Issues resolved since last scan ({len(resolved)}): "
        f"{json.dumps([i.get('issue') for i in resolved])}\n"
        f"New issues found ({len(new_issues)}): "
        f"{json.dumps([i.get('issue') for i in new_issues])}\n"
        f"Issues still present ({len(persisting)}): "
        f"{json.dumps([i.get('issue') for i in persisting])}\n\n"
        "Write a short, plain-English summary (2-4 sentences) for the developer. "
        "Mention what improved, flag any new regressions if they exist, and note what still needs work. "
        "Be direct and practical — no fluff."
    )

    result = await call_ai(prompt, temperature=0.4)
    return result or "Could not generate diff narrative."
