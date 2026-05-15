"""
Interactive REPL
================
Post-scan Q&A loop — the "Gemini CLI feel".

After a scan completes, the user drops into this loop where they can:
  - Ask natural-language questions about the scan results
  - Use slash commands (/export, /files, /model, /clear, /help)
  - Ctrl+C to exit

The AI is given full scan context at the start of the conversation
and remembers the entire chat history during the session.
"""

import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console

from securelens.ai import call_ai
from securelens.ai.prompts import chat_prompt
from securelens.output import console, print_ai_response, print_info, print_error, print_success
from securelens.output.exporters import save_json, save_markdown

console_out = Console()

HELP_TEXT = """
[bold cyan]Available commands:[/bold cyan]

  [bold]/help[/bold]              Show this help message
  [bold]/files[/bold]             List files that were scanned
  [bold]/score[/bold]             Show the security score
  [bold]/export markdown[/bold]   Save the report as a Markdown file
  [bold]/export json[/bold]       Save the report as a JSON file
  [bold]/model <name>[/bold]      Switch AI model (e.g. /model gpt-4o-mini)
  [bold]/clear[/bold]             Clear the terminal
  [bold]/exit[/bold]              Exit the REPL

Or just type a question in plain English, e.g.:
  [dim]> How do I fix the SQL injection?[/dim]
  [dim]> What's the most critical issue?[/dim]
  [dim]> Show me all issues in auth.py[/dim]
"""


@dataclass
class ReplContext:
    target: str
    scan_result: object        # LocalScanResult or WebScanResult
    target_type: str           # "code" | "web"
    api_key: str
    model: str
    conversation_history: list = field(default_factory=list)


async def run_repl(ctx: ReplContext) -> None:
    """
    Enter the interactive REPL. Blocks until the user exits.
    """
    # Build initial scan context string (injected into every AI prompt)
    scan_ctx_str = _build_scan_context(ctx)

    console_out.print()
    console_out.print("[bold cyan]💬 Ask a follow-up[/bold cyan] [dim](or press Ctrl+C / type /exit to quit)[/dim]")
    console_out.print("[dim]Type /help for available commands[/dim]")
    console_out.print()

    while True:
        try:
            user_input = _prompt_user()
        except (KeyboardInterrupt, EOFError):
            console_out.print("\n[dim]Goodbye![/dim]\n")
            break

        user_input = user_input.strip()
        if not user_input:
            continue

        # ── Slash commands ──────────────────────────────────────────────────
        if user_input.startswith("/"):
            should_exit = await _handle_slash_command(user_input, ctx)
            if should_exit:
                break
            continue

        # ── AI response ─────────────────────────────────────────────────────
        if not ctx.api_key:
            print_error("No API key configured. Run `securelens configure` to set one.")
            continue

        prompt = chat_prompt(ctx.target, scan_ctx_str, user_input)
        console_out.print("[dim]  Thinking...[/dim]")
        response = await call_ai(
            prompt=prompt,
            api_key=ctx.api_key,
            model=ctx.model,
            temperature=0.5,
            conversation_history=ctx.conversation_history,
        )

        if response:
            # Save to history for multi-turn context
            ctx.conversation_history.append({"role": "user", "content": user_input})
            ctx.conversation_history.append({"role": "assistant", "content": response})
            print_ai_response(response)
        else:
            print_error("No response from AI. Check your API key and network connection.")


def _prompt_user() -> str:
    """Read a line from stdin with a styled prompt."""
    sys.stdout.write("[dim bold cyan]>[/dim bold cyan] ")
    sys.stdout.flush()
    # Use input() — rich.prompt not used here to keep it simple
    try:
        from rich.prompt import Prompt
        return Prompt.ask("[bold cyan]>[/bold cyan]")
    except Exception:
        return input("> ")


def _build_scan_context(ctx: ReplContext) -> str:
    """Serialize the scan result into a compact string for the AI context."""
    result = ctx.scan_result
    if ctx.target_type == "code":
        vulns = [
            {
                "file": v.file_path,
                "line": v.line_number,
                "severity": v.severity,
                "issue": v.issue,
                "explanation": v.explanation,
                "fix": v.suggested_fix,
            }
            for v in result.vulnerabilities
        ]
        return json.dumps({
            "target": result.target,
            "score": result.score,
            "grade": result.grade,
            "files_scanned": result.files_triaged,
            "vulnerabilities": vulns,
            "ai_summary": result.ai_summary,
        }, indent=2)
    else:  # web
        issues = [
            {"layer": i.layer, "severity": i.severity, "issue": i.issue, "fix": i.fix}
            for i in result.issues
        ]
        return json.dumps({
            "target": result.url,
            "score": result.score,
            "grade": result.grade,
            "ssl_expiry_days": result.ssl_expiry_days,
            "exposed_paths": result.exposed_paths,
            "issues": issues,
            "ai_summary": result.ai_summary,
        }, indent=2)


async def _handle_slash_command(cmd: str, ctx: ReplContext) -> bool:
    """
    Process a slash command. Returns True if the REPL should exit.
    """
    parts = cmd.split()
    command = parts[0].lower()

    if command == "/exit":
        console_out.print("\n[dim]Goodbye![/dim]\n")
        return True

    elif command == "/help":
        console_out.print(HELP_TEXT)

    elif command == "/clear":
        console_out.clear()

    elif command == "/files":
        result = ctx.scan_result
        if ctx.target_type == "code" and hasattr(result, "files_triaged"):
            console_out.print("\n[bold]Files analyzed:[/bold]")
            for f in result.files_triaged:
                console_out.print(f"  [dim]• {f}[/dim]")
            console_out.print()
        else:
            print_info("File list not available for web scans.")

    elif command == "/score":
        r = ctx.scan_result
        score = r.score
        grade = r.grade
        console_out.print(f"\n  [bold]Score:[/bold] {score}/100  [bold]Grade:[/bold] {grade}\n")

    elif command == "/model":
        if len(parts) < 2:
            print_info(f"Current model: {ctx.model}")
            print_info("Usage: /model <model-name>  e.g. /model gpt-4o-mini")
        else:
            ctx.model = parts[1]
            print_success(f"Model switched to: {ctx.model}")

    elif command == "/export":
        fmt = parts[1].lower() if len(parts) > 1 else "markdown"
        if fmt == "json":
            path = save_json(ctx.scan_result, ctx.target_type)
            print_success(f"JSON report saved to: {path}")
        else:
            path = save_markdown(ctx.scan_result, ctx.target_type)
            print_success(f"Markdown report saved to: {path}")

    else:
        print_error(f"Unknown command: {command}. Type /help for available commands.")

    return False
