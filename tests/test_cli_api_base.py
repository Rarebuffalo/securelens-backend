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

@pytest.mark.asyncio
async def test_triage_files_passes_api_base():
    from securelens.scanners import triage_files
    from securelens.config import CLIConfig
    from pathlib import Path
    
    cfg = CLIConfig()
    cfg.api_key = "mock_key"
    cfg.api_base = "https://agentrouter.org/v1"
    cfg.default_model = "openai/deepseek-chat"
    
    with patch("securelens.scanners.call_ai_json", new_callable=AsyncMock) as mock_call_ai_json:
        mock_call_ai_json.return_value = {"critical_files": []}
        
        await triage_files([Path("test.py")], Path("."), cfg)
        
        mock_call_ai_json.assert_called_once()
        called_kwargs = mock_call_ai_json.call_args[1]
        assert called_kwargs["api_base"] == "https://agentrouter.org/v1"

@pytest.mark.asyncio
async def test_analyze_file_passes_api_base():
    from securelens.scanners import analyze_file
    from securelens.config import CLIConfig
    from pathlib import Path
    
    cfg = CLIConfig()
    cfg.api_key = "mock_key"
    cfg.api_base = "https://agentrouter.org/v1"
    cfg.default_model = "openai/deepseek-chat"
    
    mock_file = Path("test.py")
    with patch("pathlib.Path.read_text", return_value="print('hello')"):
        with patch("securelens.scanners.call_ai_json", new_callable=AsyncMock) as mock_call_ai_json:
            mock_call_ai_json.return_value = {"vulnerabilities": []}
            
            await analyze_file(mock_file, Path("."), cfg)
            
            mock_call_ai_json.assert_called_once()
            called_kwargs = mock_call_ai_json.call_args[1]
            assert called_kwargs["api_base"] == "https://agentrouter.org/v1"

@pytest.mark.asyncio
async def test_call_ai_injects_agentrouter_headers():
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
        assert called_kwargs["extra_headers"] == {
            "Originator": "codex_cli_rs",
            "User-Agent": "codex_cli_rs/0.101.0 (Mac OS 26.0.1; arm64) Apple_Terminal/464",
            "Version": "0.101.0",
        }
