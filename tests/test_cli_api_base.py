from unittest.mock import AsyncMock, patch
import pytest
from securelens.ai import call_ai

@pytest.fixture(autouse=True)
def setup_db():
    pass

@pytest.mark.asyncio
async def test_call_ai_passes_api_base():
    with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
        mock_acompletion.return_value.choices = [
            AsyncMock(message=AsyncMock(content="Mock response"))
        ]
        
        await call_ai(
            prompt="Hello",
            api_key="mock_key",
            model="openai/deepseek-chat",
            api_base="https://agentrouter.org/v1"
        )
        
        mock_acompletion.assert_called_once()
        called_kwargs = mock_acompletion.call_args[1]
        assert called_kwargs["api_base"] == "https://agentrouter.org/v1"
        assert called_kwargs["model"] == "openai/deepseek-chat"
        assert called_kwargs["api_key"] == "mock_key"

@pytest.mark.asyncio
async def test_backend_call_ai_passes_api_base():
    from app.services.ai import call_ai as backend_call_ai
    from app.config import settings
    
    with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
        mock_acompletion.return_value.choices = [
            AsyncMock(message=AsyncMock(content="Mock response"))
        ]
        
        original_key = settings.ai_api_key
        original_base = settings.ai_api_base
        
        try:
            settings.ai_api_key = "mock_key"
            settings.ai_api_base = "https://agentrouter.org/v1"
            
            await backend_call_ai(prompt="Hello")
            
            mock_acompletion.assert_called_once()
            called_kwargs = mock_acompletion.call_args[1]
            assert called_kwargs["api_base"] == "https://agentrouter.org/v1"
            assert called_kwargs["api_key"] == "mock_key"
        finally:
            settings.ai_api_key = original_key
            settings.ai_api_base = original_base
