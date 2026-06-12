"""
Interactive REPL
================
Post-scan Q&A loop — the "Gemini CLI feel".

After a scan completes, the user drops into this loop where they can:
  - Ask natural-language questions about the scan results
  - Use slash commands (/export, /files, /score, /model, /clear, /help, /exit)
  - Ctrl+C to exit

The AI is given full scan context at the start of the conversation
and remembers the entire chat history during the session.
"""

import json
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt

from securelens.ai import call_ai
from securelens.ai.prompts import chat_prompt
from securelens.output.exporters import save_json, save_markdown

console = Console()

HELP_TEXT = """
[bold cyan]Available commands:[/bold cyan]

  [bold]/help[/bold]              Show this help message
  [bold]/files[/bold]             List files that were analyzed
  [bold]/score[/bold]             Show the current security score
  [bold]/issues[/bold]            Show all found issues (summary)
  [bold]/issues critical[/bold]   Filter issues by severity (critical/high/medium/low)
  [bold]/export markdown[/bold]   Save the report as a Markdown file
  [bold]/export json[/bold]       Save the report as a JSON file
  [bold]/export pdf[/bold]        Save the report as a PDF file
  [bold]/model <name>[/bold]      Switch AI model (e.g. /model gpt-4o-mini)
  [bold]/clear[/bold]             Clear the terminal
  [bold]/exit[/bold]              Exit the REPL

Or just type a question in plain English, e.g.:
  [dim]> How do I fix the SQL injection?[/dim]
  [dim]> What's the most critical issue?[/dim]
  [dim]> Show me all issues in auth.py[/dim]
  [dim]> Give me a step-by-step remediation plan[/dim]
"""


@dataclass
class ReplContext:
    target: str
    scan_result: object        # LocalScanResult or WebScanResult
    target_type: str           # "code" | "web" | "github"
    api_key: str
    model: str
    conversation_history: list = field(default_factory=list)


async def run_repl(ctx: ReplContext) -> None:
    """
    Enter the interactive REPL. Blocks until the user exits.
    """
    # Build scan context string once — injected into every AI prompt
    scan_ctx_str = _build_scan_context(ctx)

    console.print()
    console.rule("[bold cyan] SecureLens AI Chat [/bold cyan]", style="cyan")
    console.print(
        "[dim]Ask anything about the scan results. "
        "Type [bold]/help[/bold] for commands, [bold]Ctrl+C[/bold] to exit.[/dim]\n"
    )

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]>[/bold cyan]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye![/dim]\n")
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
            console.print(
                "\n  [bold red]✗ No API key configured.[/bold red] "
                "Run [cyan]securelens configure[/cyan] to set one.\n"
            )
            continue

        # Show a thinking indicator
        with console.status("[dim]Thinking...[/dim]", spinner="dots"):
            prompt = chat_prompt(ctx.target, scan_ctx_str, user_input)
            response = await call_ai(
                prompt=prompt,
                api_key=ctx.api_key,
                model=ctx.model,
                temperature=0.5,
                conversation_history=ctx.conversation_history,
            )

        if response:
            # Append to history for multi-turn context (cap at 20 turns to avoid token bloat)
            ctx.conversation_history.append({"role": "user", "content": user_input})
            ctx.conversation_history.append({"role": "assistant", "content": response})
            if len(ctx.conversation_history) > 40:
                ctx.conversation_history = ctx.conversation_history[-40:]

            # Render AI response as Markdown (handles code blocks, bullets, headers)
            console.print()
            console.print(Panel(
                Markdown(response),
                border_style="dim cyan",
                padding=(0, 1),
            ))
            console.print()
        else:
            console.print(
                "\n  [bold red]✗ No response from AI.[/bold red] "
                "Check your API key and network connection.\n"
            )


# ── Scan context builder ──────────────────────────────────────────────────────

def _build_scan_context(ctx: ReplContext) -> str:
    """Serialize the scan result into a compact JSON string for AI context."""
    result = ctx.scan_result

    if ctx.target_type in ("code", "github"):
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


# ── Slash command dispatcher ──────────────────────────────────────────────────

async def _handle_slash_command(cmd: str, ctx: ReplContext) -> bool:
    """
    Handle a slash command. Returns True if the REPL should exit.
    """
    parts = cmd.strip().split(maxsplit=2)
    command = parts[0].lower()

    if command == "/exit":
        console.print("\n[dim]Goodbye![/dim]\n")
        return True

    elif command == "/help":
        console.print(HELP_TEXT)

    elif command == "/clear":
        console.clear()

    elif command == "/files":
        result = ctx.scan_result
        if ctx.target_type in ("code", "github") and hasattr(result, "files_triaged"):
            if result.files_triaged:
                console.print("\n[bold]Files analyzed:[/bold]")
                for f in result.files_triaged:
                    console.print(f"  [dim]• {f}[/dim]")
            else:
                console.print("\n  [dim]No files were analyzed.[/dim]")
            console.print()
        else:
            console.print("\n  [dim]File list not available for web scans.[/dim]\n")

    elif command == "/score":
        r = ctx.scan_result
        from securelens.output import GRADE_COLOR
        grade_color = GRADE_COLOR.get(r.grade, "white")
        console.print(
            f"\n  Score: [{grade_color}]{r.score}/100  Grade: {r.grade}[/{grade_color}]\n"
        )

    elif command == "/issues":
        severity_filter = parts[1].strip().lower() if len(parts) > 1 else None
        _print_issues_summary(ctx, severity_filter)

    elif command == "/model":
        if len(parts) < 2:
            console.print(f"\n  [dim]Current model: {ctx.model}[/dim]")
            console.print("  [dim]Usage: /model <model-name>  e.g. /model gpt-4o-mini[/dim]\n")
        else:
            ctx.model = parts[1]
            console.print(f"\n  [bold green]✓ Model switched to: {ctx.model}[/bold green]\n")

    elif command == "/export":
        fmt = parts[1].lower() if len(parts) > 1 else "markdown"
        target_type = "code" if ctx.target_type in ("code", "github") else "web"
        if fmt == "json":
            path = save_json(ctx.scan_result, target_type)
            console.print(f"\n  [bold green]✓ JSON report saved:[/bold green] [dim]{path}[/dim]\n")
        elif fmt == "pdf":
            from securelens.output.exporters import save_pdf
            path = save_pdf(ctx.scan_result, target_type)
            console.print(f"\n  [bold green]✓ PDF report saved:[/bold green] [dim]{path}[/dim]\n")
        else:
            path = save_markdown(ctx.scan_result, target_type)
            console.print(f"\n  [bold green]✓ Markdown report saved:[/bold green] [dim]{path}[/dim]\n")

    else:
        console.print(
            f"\n  [bold red]✗ Unknown command: {command}[/bold red] "
            "Type [cyan]/help[/cyan] for available commands.\n"
        )

    return False


def _print_issues_summary(ctx: ReplContext, severity_filter: Optional[str] = None) -> None:
    """Print a compact list of all issues, optionally filtered by severity."""
    result = ctx.scan_result
    from securelens.output import SEVERITY_COLOR

    if ctx.target_type in ("code", "github"):
        issues = result.vulnerabilities
        if not issues:
            console.print("\n  [bold green]✓ No vulnerabilities found.[/bold green]\n")
            return

        filtered = issues
        if severity_filter:
            filtered = [v for v in issues if v.severity.lower() == severity_filter]
            if not filtered:
                console.print(f"\n  [dim]No {severity_filter} issues found.[/dim]\n")
                return

        console.print(f"\n  [bold]{len(filtered)} issue(s):[/bold]")
        for i, v in enumerate(filtered, 1):
            color = SEVERITY_COLOR.get(v.severity, "white")
            loc = v.file_path
            if v.line_number:
                loc += f":{v.line_number}"
            console.print(f"  [{color}][{i}] {v.severity}[/{color}]  {v.issue}  [dim]{loc}[/dim]")
        console.print()

    else:  # web
        issues = result.issues
        if not issues:
            console.print("\n  [bold green]✓ No issues found.[/bold green]\n")
            return

        filtered = issues
        if severity_filter:
            filtered = [i for i in issues if i.severity.lower() == severity_filter]
            if not filtered:
                console.print(f"\n  [dim]No {severity_filter} issues found.[/dim]\n")
                return

        console.print(f"\n  [bold]{len(filtered)} issue(s):[/bold]")
        for i, issue in enumerate(filtered, 1):
            color = SEVERITY_COLOR.get(issue.severity, "white")
            console.print(f"  [{color}][{i}] {issue.severity}[/{color}]  {issue.issue}  [dim]{issue.layer}[/dim]")
        console.print()
