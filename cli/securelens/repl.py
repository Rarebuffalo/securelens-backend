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
    api_base: Optional[str] = None
    conversation_history: list = field(default_factory=list)


@dataclass
class ShellContext:
    api_key: Optional[str] = None
    model: str = "openai/deepseek-chat"
    api_base: Optional[str] = None
    active_result: Optional[object] = None
    target_type: Optional[str] = None  # "code" | "web"
    conversation_history: list = field(default_factory=list)


SHELL_HELP_TEXT = """
[bold cyan]Available interactive commands:[/bold cyan]

  [bold]/scan <path>[/bold]         Scan a local codebase (e.g. /scan .)
  [bold]/scan-web <url>[/bold]       Scan a live website (e.g. /scan-web https://example.com)
  [bold]/configure[/bold]            Launch the interactive configuration wizard
  [bold]/score[/bold]                Show score/grade of the active scan
  [bold]/issues[/bold]               Show a summary of found issues
  [bold]/issues <level>[/bold]       Filter issues by severity (critical/high/medium/low)
  [bold]/files[/bold]                List files analyzed in the active scan
  [bold]/export markdown[/bold]      Save active report as Markdown
  [bold]/export json[/bold]          Save active report as JSON
  [bold]/export pdf[/bold]           Save active report as PDF
  [bold]/model <name>[/bold]         Switch AI model (e.g. /model gpt-4o-mini)
  [bold]/clear[/bold]                Clear the terminal
  [bold]/exit[/bold]                 Exit the shell

Or ask a question in plain English about the active scan:
  [dim]> What is the Cassandra credentials finding?[/dim]
"""


def _make_completer(ctx: ShellContext):
    import os
    import glob
    import readline

    commands = [
        "/scan", "/scan-web", "/configure", "/score", "/issues", 
        "/files", "/export", "/model", "/clear", "/help", "/exit"
    ]
    export_formats = ["markdown", "json", "pdf"]
    severity_levels = ["critical", "high", "medium", "low"]
    common_models = [
        "gemini/gemini-2.0-flash", "gemini/gemini-1.5-pro",
        "gpt-4o-mini", "gpt-4o", "claude-3-5-haiku-20241022",
        "ollama/llama3.1", "openai/deepseek-chat"
    ]

    def completer(text, state):
        line = readline.get_line_buffer()
        words = line.split()

        # Completing the main command
        if not line or (line.startswith("/") and " " not in line):
            options = [cmd for cmd in commands if cmd.startswith(text)]
            if state < len(options):
                return options[state]
            return None

        # Completing parameters
        if len(words) >= 1:
            cmd = words[0].lower()
            if cmd == "/scan":
                prefix_start = len("/scan ")
                path_prefix = line[prefix_start:]
                
                # Expand ~ to home directory for globbing
                expanded_prefix = os.path.expanduser(path_prefix)
                
                suggestions = glob.glob(expanded_prefix + "*")
                options = []
                for s in suggestions:
                    # Put back ~ if it was typed
                    if path_prefix.startswith("~"):
                        display_s = s.replace(os.path.expanduser("~"), "~", 1)
                    else:
                        display_s = s
                        
                    if os.path.isdir(s):
                        options.append(display_s + "/")
                    else:
                        options.append(display_s)
                        
                if state < len(options):
                    return options[state]
                return None
                
            elif cmd == "/export":
                prefix_start = len("/export ")
                fmt_prefix = line[prefix_start:]
                options = [fmt for fmt in export_formats if fmt.startswith(fmt_prefix)]
                if state < len(options):
                    return options[state]
                return None
                
            elif cmd == "/issues":
                prefix_start = len("/issues ")
                sev_prefix = line[prefix_start:]
                options = [sev for sev in severity_levels if sev.startswith(sev_prefix)]
                if state < len(options):
                    return options[state]
                return None
                
            elif cmd == "/model":
                prefix_start = len("/model ")
                model_prefix = line[prefix_start:]
                options = [m for m in common_models if m.startswith(model_prefix)]
                if state < len(options):
                    return options[state]
                return None

        return None

    return completer


async def run_global_shell(ctx: ShellContext) -> None:
    import os
    import readline
    from pathlib import Path
    from urllib.parse import urlparse
    from securelens.output import print_banner
    from securelens.config import load_config
    from securelens.cli import run_local_scan_workflow

    # ── History initialization ───────────────────────────────────────────────
    history_dir = os.path.expanduser("~/.securelens")
    os.makedirs(history_dir, exist_ok=True)
    history_file = os.path.join(history_dir, "history")

    if os.path.exists(history_file):
        try:
            readline.read_history_file(history_file)
        except Exception:
            pass

    readline.set_history_length(1000)

    # ── Autocomplete initialization ──────────────────────────────────────────
    readline.set_completer(_make_completer(ctx))
    readline.set_completer_delims(" \t\n")
    if "libedit" in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

    print_banner()
    console.print("[bold cyan]Welcome to SecureLens AI Interactive Shell[/bold cyan]")
    console.print("[dim]Type [bold]/help[/bold] for a list of available commands or [bold]/exit[/bold] to quit.[/dim]\n")

    try:
        while True:
            # ── Dynamic Prompt state ─────────────────────────────────────────
            if ctx.active_result:
                if ctx.target_type == "code":
                    name = Path(ctx.active_result.target).name
                    prompt_str = f"[bold cyan]securelens [{name}] >[/bold cyan] "
                else:  # web
                    domain = urlparse(ctx.active_result.url).netloc or ctx.active_result.url
                    prompt_str = f"[bold cyan]securelens [{domain}] >[/bold cyan] "
            else:
                prompt_str = "[bold cyan]securelens >[/bold cyan] "

            try:
                user_input = Prompt.ask(prompt_str, colon=False)
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Goodbye![/dim]\n")
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            if user_input.startswith("/"):
                should_exit = await _handle_global_slash_command(user_input, ctx)
                if should_exit:
                    break
                continue

            # Chat logic about active scan result
            if not ctx.active_result:
                console.print("\n  [bold yellow]⚠ No active scan loaded.[/bold yellow] Run a scan first: [cyan]/scan .[/cyan]\n")
                continue

            if not ctx.api_key and not ctx.model.startswith("ollama/"):
                console.print(
                    "\n  [bold red]✗ No API key configured.[/bold red] "
                    "Run [cyan]/configure[/cyan] to set one.\n"
                )
                continue

            # Setup standard ReplContext so we can use existing _build_scan_context
            repl_ctx = ReplContext(
                target=ctx.active_result.target if ctx.target_type == "code" else ctx.active_result.url,
                scan_result=ctx.active_result,
                target_type=ctx.target_type,
                api_key=ctx.api_key,
                model=ctx.model,
                api_base=ctx.api_base,
                conversation_history=ctx.conversation_history,
            )
            scan_ctx_str = _build_scan_context(repl_ctx)

            with console.status("[dim]Thinking...[/dim]", spinner="dots"):
                prompt = chat_prompt(repl_ctx.target, scan_ctx_str, user_input)
                response = await call_ai(
                    prompt=prompt,
                    api_key=ctx.api_key,
                    model=ctx.model,
                    temperature=0.5,
                    conversation_history=ctx.conversation_history,
                    api_base=ctx.api_base,
                )

            if response:
                ctx.conversation_history.append({"role": "user", "content": user_input})
                ctx.conversation_history.append({"role": "assistant", "content": response})
                if len(ctx.conversation_history) > 40:
                    ctx.conversation_history = ctx.conversation_history[-40:]

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
    finally:
        # ── Save history ─────────────────────────────────────────────────────
        try:
            readline.write_history_file(history_file)
        except Exception:
            pass


async def _handle_global_slash_command(cmd: str, ctx: ShellContext) -> bool:
    parts = cmd.strip().split(maxsplit=2)
    command = parts[0].lower()

    if command == "/exit":
        console.print("\n[dim]Goodbye![/dim]\n")
        return True

    elif command == "/help":
        console.print(SHELL_HELP_TEXT)

    elif command == "/clear":
        console.clear()

    elif command == "/configure":
        from securelens.cli import configure
        configure.callback()

    elif command in ("/scan", "/scan-web"):
        from securelens.config import load_config
        from securelens.cli import run_local_scan_workflow, run_web_scan_workflow

        cfg = load_config()
        ctx.api_key = cfg.api_key
        ctx.api_base = cfg.api_base
        ctx.model = cfg.default_model

        if command == "/scan":
            path = parts[1] if len(parts) > 1 else "."
            no_ai = not ctx.api_key
            result = await run_local_scan_workflow(
                path=path,
                cfg=cfg,
                no_ai=no_ai,
                sync=False,
                ci=False,
            )
            if result:
                ctx.active_result = result
                ctx.target_type = "code"
                ctx.conversation_history.clear()
        else:  # /scan-web
            if len(parts) < 2:
                console.print("\n  [bold red]✗ Error: Missing URL.[/bold red] Usage: /scan-web <url>\n")
                return False
            url = parts[1]
            no_ai = not ctx.api_key
            result = await run_web_scan_workflow(
                url=url,
                cfg=cfg,
                no_ai=no_ai,
                ci=False,
            )
            if result:
                ctx.active_result = result
                ctx.target_type = "web"
                ctx.conversation_history.clear()

    elif command == "/model":
        if len(parts) < 2:
            console.print(f"\n  [dim]Current model: {ctx.model}[/dim]")
            console.print("  [dim]Usage: /model <model-name>[/dim]\n")
        else:
            ctx.model = parts[1]
            console.print(f"\n  [bold green]✓ Model switched to: {ctx.model}[/bold green]\n")

    elif command in ("/score", "/issues", "/files", "/export"):
        if not ctx.active_result:
            console.print("\n  [bold yellow]⚠ No active scan loaded.[/bold yellow] Run a scan first: [cyan]/scan .[/cyan]\n")
            return False

        repl_ctx = ReplContext(
            target=ctx.active_result.target if ctx.target_type == "code" else ctx.active_result.url,
            scan_result=ctx.active_result,
            target_type=ctx.target_type,
            api_key=ctx.api_key or "",
            model=ctx.model,
            api_base=ctx.api_base,
            conversation_history=ctx.conversation_history,
        )

        if command == "/score":
            r = ctx.active_result
            from securelens.output import GRADE_COLOR
            grade_color = GRADE_COLOR.get(r.grade, "white")
            console.print(
                f"\n  Score: [{grade_color}]{r.score}/100  Grade: {r.grade}[/{grade_color}]\n"
            )

        elif command == "/issues":
            severity_filter = parts[1].strip().lower() if len(parts) > 1 else None
            _print_issues_summary(repl_ctx, severity_filter)

        elif command == "/files":
            result = ctx.active_result
            if ctx.target_type == "code" and hasattr(result, "files_triaged"):
                if result.files_triaged:
                    console.print("\n[bold]Files analyzed:[/bold]")
                    for f in result.files_triaged:
                        console.print(f"  [dim]• {f}[/dim]")
                else:
                    console.print("\n  [dim]No files were analyzed.[/dim]")
                console.print()
            else:
                console.print("\n  [dim]File list not available for web scans.[/dim]\n")

        elif command == "/export":
            fmt = parts[1].lower() if len(parts) > 1 else "markdown"
            target_type = "code" if ctx.target_type == "code" else "web"
            if fmt == "json":
                path = save_json(ctx.active_result, target_type)
                console.print(f"\n  [bold green]✓ JSON report saved:[/bold green] [dim]{path}[/dim]\n")
            elif fmt == "pdf":
                from securelens.output.exporters import save_pdf
                path = save_pdf(ctx.active_result, target_type)
                console.print(f"\n  [bold green]✓ PDF report saved:[/bold green] [dim]{path}[/dim]\n")
            else:
                path = save_markdown(ctx.active_result, target_type)
                console.print(f"\n  [bold green]✓ Markdown report saved:[/bold green] [dim]{path}[/dim]\n")

    else:
        console.print(
            f"\n  [bold red]✗ Unknown command: {command}[/bold red] "
            "Type [cyan]/help[/cyan] for available commands.\n"
        )

    return False


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
        if not ctx.api_key and not ctx.model.startswith("ollama/"):
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
                api_base=ctx.api_base,
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
