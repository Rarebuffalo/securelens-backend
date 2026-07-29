from unittest.mock import AsyncMock, patch
import pytest
from securelens.repl import run_global_shell, ShellContext

@pytest.fixture(autouse=True)
def setup_db_override():
    # Override database fixture because these are pure CLI / REPL unit tests
    pass

@pytest.mark.asyncio
async def test_global_shell_help_and_exit():
    ctx = ShellContext(
        api_key="mock_key",
        model="openai/deepseek-chat",
    )
    
    inputs = ["/help", "/exit"]
    input_idx = 0
    
    def mock_ask(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    with patch("securelens.repl.Prompt.ask", side_effect=mock_ask):
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
    
    def mock_ask(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    with patch("securelens.repl.Prompt.ask", side_effect=mock_ask):
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
    
    def mock_ask(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    with patch("securelens.repl.Prompt.ask", side_effect=mock_ask):
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
    
    def mock_ask(*args, **kwargs):
        nonlocal input_idx
        val = inputs[input_idx]
        input_idx += 1
        return val
        
    mock_result = AsyncMock()
    mock_result.target = "/mock/target"
    mock_result.grade = "A"
    mock_result.score = 100
    mock_result.vulnerabilities = []
    
    with patch("securelens.repl.Prompt.ask", side_effect=mock_ask):
        with patch("securelens.cli.run_local_scan_workflow", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = mock_result
            await run_global_shell(ctx)
            
            mock_scan.assert_called_once()
            assert ctx.active_result == mock_result
            assert ctx.target_type == "code"
