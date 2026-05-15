"""
AI Client
=========
Thin, model-agnostic wrapper around LiteLLM.
The CLI uses this instead of directly calling litellm
so we have one place to handle retries, logging, and key injection.
"""

import json
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def call_ai(
    prompt: str,
    api_key: str,
    model: str,
    temperature: float = 0.3,
    json_mode: bool = False,
    conversation_history: Optional[list] = None,
) -> str:
    """
    Single entry-point for all AI calls in the CLI.

    Parameters
    ----------
    prompt               : The prompt to send (added as last user message)
    api_key              : LiteLLM-compatible API key
    model                : LiteLLM model string (e.g. "gemini/gemini-2.0-flash")
    temperature          : Creativity (0=deterministic, 1=creative)
    json_mode            : Ask the model to respond with valid JSON only
    conversation_history : Optional list of {"role": ..., "content": ...} dicts
                           for multi-turn chat sessions
    """
    import litellm

    litellm.suppress_debug_info = True

    messages = list(conversation_history or [])
    messages.append({"role": "user", "content": prompt})

    kwargs: dict = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "api_key": api_key if api_key else None,
    }

    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    try:
        response = await litellm.acompletion(**kwargs)
        return response.choices[0].message.content or ""
    except Exception as e:
        logger.error(f"AI call failed [{model}]: {e}")
        return ""


async def call_ai_json(
    prompt: str,
    api_key: str,
    model: str,
    temperature: float = 0.2,
) -> Optional[dict]:
    """Convenience wrapper — calls AI in JSON mode and parses the result."""
    raw = await call_ai(prompt, api_key, model, temperature=temperature, json_mode=True)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse failed: {e}\nRaw: {raw[:300]}")
        return None
