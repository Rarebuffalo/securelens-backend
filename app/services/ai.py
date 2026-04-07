import json
import logging
from openai import AsyncOpenAI
from app.config import settings

logger = logging.getLogger(__name__)

api_key = settings.openai_api_key or "mock-key-for-testing"
client = AsyncOpenAI(api_key=api_key)

async def enhance_security_issues(issues: list[dict]) -> dict:
    """
    Takes a list of basic security issues and uses an LLM to provide:
    - Contextual severity
    - Natural language explanations
    - Auto-generated remediation code snippets
    """
    if not settings.openai_api_key:
        logger.warning("OPENAI_API_KEY is not set. AI enhancements are skipped.")
        return {"enhanced_issues": issues}

    prompt = (
        "Analyze the following security vulnerabilities:\n"
        f"{json.dumps(issues, indent=2)}\n\n"
        "Return a JSON object with a single key 'enhanced_issues' containing a list of objects. "
        "Each object MUST correspond to one of the original issues and have the following keys: "
        "'issue' (exact string of the original issue), "
        "'contextual_severity' (Low, Medium, High, Critical), "
        "'explanation' (a 1-2 sentence non-technical explanation), "
        "'remediation_snippet' (Actionable code snippet, e.g. Nginx config, or 'N/A')."
    )

    try:
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity automation agent. Always respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        content = response.choices[0].message.content
        if not content:
            return {"enhanced_issues": issues, "ai_error": "Empty response"}
            
        return json.loads(content)
    except Exception as e:
        logger.error(f"AI Generation Error: {str(e)}")
        return {"enhanced_issues": issues, "ai_error": str(e)}

async def chat_with_scan_context(scan_id: str, context_data: dict, user_message: str) -> str:
    """
    Allows a user to ask a question about a specific scan's results.
    """
    if not settings.openai_api_key:
        return "AI Chat is disabled because OPENAI_API_KEY is not configured."

    system_prompt = (
        "You are SecureLens AI, an expert cybersecurity assistant. "
        "You are helping a developer understand a security scan report for their website. "
        f"Here is the context of the scan: {json.dumps(context_data)}"
    )

    try:
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            temperature=0.5,
        )
        return response.choices[0].message.content or "No response from AI."
    except Exception as e:
        logger.error(f"AI Chat Error: {str(e)}")
        return "I encountered an error trying to process your request."

async def generate_threat_narrative(context_data: dict) -> str:
    """
    Weaves multiple scan issues into a cohesive attack sequence.
    """
    if not settings.openai_api_key:
        return "AI Threat Narrative is disabled because OPENAI_API_KEY is not configured."

    system_prompt = (
        "You are a senior cybersecurity red-teamer. Analyze the following security scan results "
        "and weave them into a single, cohesive 'Threat Narrative'. Explain how an attacker might "
        "chain these specific vulnerabilities together to compromise the system. "
        "Keep it professional, concise (2-3 paragraphs), and actionable."
    )

    try:
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(context_data)}
            ],
            temperature=0.7,
        )
        return response.choices[0].message.content or "Could not generate threat narrative."
    except Exception as e:
        logger.error(f"AI Narrative Error: {str(e)}")
        return "I encountered an error trying to generate the threat narrative."
