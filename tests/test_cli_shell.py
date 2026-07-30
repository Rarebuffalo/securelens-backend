from unittest.mock import AsyncMock, patch
import pytest
from securelens.repl import run_global_shell, ShellContext, SecureLensCompleter, SecureLensAutoSuggest
from prompt_toolkit.document import Document

@pytest.fixture(autouse=True)
def setup_db_override(monkeypatch):
    # Set SECURELENS_TESTING so we bypass automatic startup scanning
    monkeypatch.setenv("SECURELENS_TESTING", "1")

@pytest.mark.asyncio
async def test_global_shell_help_and_exit():
    ctx = ShellContext(
        api_key="mock_key",
        model="openai/deepseek-chat",
    )
    
    inputs = ["/help", "/exit"]
    input_idx = 0
    
    async def mock_prompt(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    with patch("prompt_toolkit.PromptSession.prompt_async", new_callable=AsyncMock) as mock_p:
        mock_p.side_effect = mock_prompt
        with patch("securelens.repl.console.print") as mock_print:
            await run_global_shell(ctx)
            mock_print.assert_any_call("\n[dim]Goodbye![/dim]\n")

@pytest.mark.asyncio
async def test_global_shell_warns_no_scan():
    ctx = ShellContext(
        api_key="mock_key",
        model="openai/deepseek-chat",
    )
    
    inputs = ["What issues did you find?", "/exit"]
    input_idx = 0
    
    async def mock_prompt(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    with patch("prompt_toolkit.PromptSession.prompt_async", new_callable=AsyncMock) as mock_p:
        mock_p.side_effect = mock_prompt
        with patch("securelens.repl.console.print") as mock_print:
            await run_global_shell(ctx)
            mock_print.assert_any_call("\n  [bold yellow]⚠ No active scan loaded.[/bold yellow] Run a scan first: [cyan]/scan .[/cyan]\n")

@pytest.mark.asyncio
async def test_global_shell_switch_model():
    ctx = ShellContext(
        api_key="mock_key",
        model="openai/deepseek-chat",
    )
    
    inputs = ["/model gpt-4o", "/exit"]
    input_idx = 0
    
    async def mock_prompt(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    with patch("prompt_toolkit.PromptSession.prompt_async", new_callable=AsyncMock) as mock_p:
        mock_p.side_effect = mock_prompt
        await run_global_shell(ctx)
        assert ctx.model == "gpt-4o"

@pytest.mark.asyncio
async def test_global_shell_scan_command_routing():
    ctx = ShellContext(
        api_key="mock_key",
        model="openai/deepseek-chat",
    )
    
    inputs = ["/scan .", "/exit"]
    input_idx = 0
    
    async def mock_prompt(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    mock_result = AsyncMock()
    mock_result.target = "/mock/target"
    mock_result.grade = "A"
    mock_result.score = 100
    mock_result.vulnerabilities = []
    
    with patch("prompt_toolkit.PromptSession.prompt_async", new_callable=AsyncMock) as mock_p:
        mock_p.side_effect = mock_prompt
        with patch("securelens.cli.run_local_scan_workflow", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = mock_result
            await run_global_shell(ctx)
            
            mock_scan.assert_called_once()
            assert ctx.active_result == mock_result
            assert ctx.target_type == "code"

def test_shell_autocomplete_commands():
    ctx = ShellContext()
    completer = SecureLensCompleter(ctx)
    
    doc = Document("/sc", cursor_position=3)
    completions = list(completer.get_completions(doc, None))
    
    assert len(completions) == 3
    assert completions[0].text == "/scan"
    assert completions[1].text == "/scan-web"

def test_shell_autocomplete_exports():
    ctx = ShellContext()
    completer = SecureLensCompleter(ctx)
    
    doc = Document("/export pd", cursor_position=10)
    completions = list(completer.get_completions(doc, None))
    
    assert len(completions) == 1
    assert completions[0].text == "pdf"

def test_shell_autosuggest():
    autosuggest = SecureLensAutoSuggest()
    
    with patch("glob.glob", return_value=["/home/user/project/tests"]):
        with patch("os.path.isdir", return_value=True):
            doc = Document("/scan /home/user/project/te")
            suggestion = autosuggest.get_suggestion(None, doc)
            
            assert suggestion is not None
            assert suggestion.text == "sts/"
