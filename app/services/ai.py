import json
import logging
import asyncio
from google import genai
from google.genai import types
from app.config import settings

logger = logging.getLogger(__name__)

if settings.gemini_api_key:
    # Initialize google-genai client
    ai_client = genai.Client(api_key=settings.gemini_api_key)
else:
    ai_client = None

async def get_gemini_model():
    return 'gemini-2.0-flash'

async def enhance_security_issues(issues: list[dict]) -> dict:
    if not settings.gemini_api_key:
        logger.warning("GEMINI_API_KEY is not set. AI enhancements are skipped.")
        return {"enhanced_issues": issues}

    prompt = (
        "You are a senior cybersecurity automation agent. Always respond with valid JSON.\n"
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
        model_name = await get_gemini_model()
        response = await ai_client.aio.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            )
        )
        if response.text:
            return json.loads(response.text)
        return {"enhanced_issues": issues, "ai_error": "Empty response"}
    except Exception as e:
        logger.error(f"AI Generation Error: {str(e)}")
        return {"enhanced_issues": issues, "ai_error": str(e)}

async def chat_with_scan_context(scan_id: str, context_data: dict, user_message: str) -> str:
    if not settings.gemini_api_key:
        return "AI Chat is disabled because GEMINI_API_KEY is not configured."

    prompt = (
        "You are SecureLens AI, an expert cybersecurity assistant. "
        "You are helping a developer understand a security scan report for their website. "
        f"Here is the context of the scan: {json.dumps(context_data)}\n\n"
        f"User Message: {user_message}"
    )

    try:
        model_name = await get_gemini_model()
        response = await ai_client.aio.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.5,
            )
        )
        return response.text or "No response from AI."
    except Exception as e:
        logger.error(f"AI Chat Error: {str(e)}")
        return "I encountered an error trying to process your request."

async def generate_threat_narrative(context_data: dict) -> str:
    if not settings.gemini_api_key:
        return "AI Threat Narrative is disabled because GEMINI_API_KEY is not configured."

    prompt = (
        "You are a senior cybersecurity red-teamer. Analyze the following security scan results "
        "and weave them into a single, cohesive 'Threat Narrative'. Explain how an attacker might "
        "chain these specific vulnerabilities together to compromise the system. "
        "Keep it professional, concise (2-3 paragraphs), and actionable.\n\n"
        f"Context: {json.dumps(context_data)}"
    )

    try:
        model_name = await get_gemini_model()
        response = await ai_client.aio.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.7,
            )
        )
        return response.text or "Could not generate threat narrative."
    except Exception as e:
        logger.error(f"AI Narrative Error: {str(e)}")
        return "I encountered an error trying to generate the threat narrative."
