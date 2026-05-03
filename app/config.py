"""
Application Configuration
==========================

All configuration is loaded from environment variables (or a .env file).

AI Provider Configuration
--------------------------
SecureLens supports multiple AI providers via LiteLLM.
Set AI_MODEL and AI_API_KEY in your .env to choose a provider:

  Provider     | AI_MODEL example                     | Where to get key
  -------------|--------------------------------------|-----------------------------
  Gemini       | gemini/gemini-2.0-flash              | aistudio.google.com
  OpenAI       | gpt-4o-mini                          | platform.openai.com
  Claude       | claude-3-5-haiku-20241022            | console.anthropic.com
  OpenRouter   | openrouter/google/gemini-2.0-flash   | openrouter.ai
  Ollama       | ollama/llama3.1                      | ollama.com (local, no key)

If you only set GEMINI_API_KEY (legacy), it will still work — the app
automatically maps it to the Gemini provider for backward compatibility.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SecureLens AI"
    app_version: str = "1.1.0"
    debug: bool = False

    host: str = "0.0.0.0"
    port: int = 8000

    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    rate_limit: str = "30/minute"

    scan_timeout: int = 5
    path_check_timeout: int = 3

    database_url: str = "postgresql+asyncpg://securelens:securelens@localhost:5433/securelens"

    jwt_secret: str = "change-me-in-production-use-a-long-random-string"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 1440

    # -------------------------------------------------------------------------
    # AI Provider Settings (new, provider-agnostic)
    # -------------------------------------------------------------------------
    # AI_MODEL: the LiteLLM model string (see table in module docstring above)
    ai_model: str = "gemini/gemini-2.0-flash"

    # AI_API_KEY: the API key for the chosen provider.
    # Leave blank for Ollama (local, no key needed).
    ai_api_key: str | None = None

    # -------------------------------------------------------------------------
    # Legacy Gemini key — kept for backward compatibility.
    # If AI_API_KEY is not set but GEMINI_API_KEY is, we use that automatically.
    # -------------------------------------------------------------------------
    gemini_api_key: str | None = None

    # Threat Intelligence API keys (Step 3)
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def effective_ai_key(self) -> str | None:
        """
        Returns the resolved AI API key.
        Prefers AI_API_KEY; falls back to GEMINI_API_KEY for backward compatibility.
        """
        return self.ai_api_key or self.gemini_api_key


settings = Settings()
