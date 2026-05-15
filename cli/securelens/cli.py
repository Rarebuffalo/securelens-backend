"""
SecureLens AI — CLI Entry Point
================================
All Click commands live here.

Commands:
  securelens configure         Interactive setup wizard
  securelens scan <path>       Scan a local codebase
  securelens web <url>         Scan a URL
  securelens version           Print version info
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine from a sync Click command."""
    return asyncio.run(coro)


def _require_config(cfg):
    """Exit early with a friendly message if no API key is set."""
    if not cfg.api_key:
        console.print(
            "\n[bold yellow]⚠ No API key configured.[/bold yellow]\n"
            "  Run [bold cyan]securelens configure[/bold cyan] to set one up.\n"
            "  Or set the [dim]SECURELENS_API_KEY[/dim] environment variable.\n"
        )
        sys.exit(1)


# ── Main group ─────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("2.0.0", prog_name="SecureLens AI")
def main():
    """
    \b
    SecureLens AI — AI-powered security scanner
    Scan codebases, URLs and get instant security reports.
    """
    pass


# ── configure ─────────────────────────────────────────────────────────────────

@main.command()
def configure():
    """Interactive setup wizard — saves config to ~/.securelens/config.yaml"""
    from securelens.config import load_config, save_config, CONFIG_FILE
    from securelens.output import print_banner

    print_banner()
    console.print("[bold]Setup Wizard[/bold]\n")

    cfg = load_config()

    # Provider selection
    providers = {
        "1": ("gemini/gemini-2.0-flash",  "Google Gemini 2.0 Flash [free tier available]"),
        "2": ("gemini/gemini-1.5-pro",    "Google Gemini 1.5 Pro"),
        "3": ("gpt-4o-mini",              "OpenAI GPT-4o Mini"),
        "4": ("gpt-4o",                   "OpenAI GPT-4o"),
        "5": ("claude-3-5-haiku-20241022","Anthropic Claude 3.5 Haiku"),
        "6": ("ollama/llama3.1",          "Ollama (local, no key needed)"),
        "7": ("custom",                   "Custom model string"),
    }
    console.print("[bold]Choose AI Provider:[/bold]")
    for k, (_, desc) in providers.items():
        console.print(f"  [{k}] {desc}")
    console.print()

    choice = Prompt.ask("Select", choices=list(providers.keys()), default="1")
    model_str, _ = providers[choice]

    if model_str == "custom":
        model_str = Prompt.ask("Enter LiteLLM model string (e.g. openrouter/google/gemini-flash)")

    cfg.default_model = model_str

    # API key (skip for Ollama)
    if not model_str.startswith("ollama/"):
        key = Prompt.ask("API Key", password=True, default=cfg.api_key or "")
        cfg.api_key = key.strip()

    # Output format
    console.print("\n[bold]Default output format:[/bold]")
    console.print("  [1] terminal  (rich display)")
    console.print("  [2] markdown  (save .md file)")
    console.print("  [3] json      (machine-readable)")
    console.print("  [4] all       (terminal + save markdown)")
    fmt_choice = Prompt.ask("Select", choices=["1", "2", "3", "4"], default="1")
    cfg.output_format = {"1": "terminal", "2": "markdown", "3": "json", "4": "all"}[fmt_choice]

    save_config(cfg)
    console.print(f"\n[bold green]✓ Config saved to {CONFIG_FILE}[/bold green]")
    console.print(f"  Model:  [cyan]{cfg.default_model}[/cyan]")
    console.print(f"  Output: [cyan]{cfg.output_format}[/cyan]\n")


# ── scan ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--model",   "-m", default=None, help="Override AI model (e.g. gpt-4o-mini)")
@click.option("--output",  "-o", default=None,
              type=click.Choice(["terminal", "json", "markdown", "all"]),
              help="Output format (overrides config)")
@click.option("--max-files", default=None, type=int, help="Max files to analyze (default: 20)")
@click.option("--ci",      is_flag=True, help="CI mode: no REPL, exits with code 1 if issues found")
@click.option("--fail-on", default=None,
              type=click.Choice(["critical", "high", "medium", "low"]),
              help="In --ci mode, exit 1 if issues of this severity or above are found")
@click.option("--no-ai",   is_flag=True, help="Skip AI triage & summary (pattern-based only, faster)")
def scan(path, model, output, max_files, ci, fail_on, no_ai):
    """
    Scan a local codebase for security vulnerabilities.

    \b
    Examples:
      securelens scan .
      securelens scan ./my-project --output markdown
      securelens scan . --model gpt-4o --max-files 30
      securelens scan . --ci --fail-on high
    """
    _run(_scan_async(path, model, output, max_files, ci, fail_on, no_ai))


async def _scan_async(path, model, output, max_files, ci, fail_on, no_ai):
    from securelens.config import load_config
    from securelens.output import print_banner, print_scan_header, print_code_scan_report, make_progress, print_error
    from securelens.output.exporters import save_json, save_markdown, to_json
    from securelens.scanners import (
        discover_files, triage_files, analyze_files, LocalScanResult
    )
    from securelens.ai import call_ai
    from securelens.ai.prompts import summary_prompt
    from securelens.repl import run_repl, ReplContext

    cfg = load_config()
    if model:
        cfg.default_model = model
    if output:
        cfg.output_format = output
    if max_files:
        cfg.max_files_to_scan = max_files

    if not no_ai:
        _require_config(cfg)

    root = Path(path).resolve()

    if not ci:
        print_banner()
        print_scan_header(str(root), cfg.default_model)

    # ── Phase 1: Discover ────────────────────────────────────────────────────
    with make_progress() as progress:
        task_discover = progress.add_task(
            "[1/4] Discovering files...", total=None, detail=""
        )
        candidates = discover_files(root, cfg)
        progress.update(task_discover, completed=100, total=100,
                        detail=f"{len(candidates)} files found")

        # ── Phase 2: Triage ──────────────────────────────────────────────────
        task_triage = progress.add_task(
            "[2/4] Triaging with AI...", total=None, detail=""
        )
        if no_ai:
            # In --no-ai mode just take the top N by sensitivity heuristic
            from securelens.scanners import _is_always_scan
            triaged = [p for p in candidates if _is_always_scan(p)][:cfg.max_files_to_scan]
        else:
            triaged = await triage_files(candidates, root, cfg)
        progress.update(task_triage, completed=100, total=100,
                        detail=f"{len(triaged)} files selected")

        # ── Phase 3: Analyze ─────────────────────────────────────────────────
        task_analyze = progress.add_task(
            "[3/4] Analyzing security...", total=len(triaged), detail=""
        )
        analyzed_count = 0

        async def on_progress(done, total, filename):
            nonlocal analyzed_count
            analyzed_count = done
            progress.update(task_analyze, completed=done, detail=filename)

        if no_ai or not cfg.api_key:
            vulnerabilities = []
        else:
            vulnerabilities = await analyze_files(triaged, root, cfg, on_progress)
        progress.update(task_analyze, completed=len(triaged),
                        detail=f"{len(vulnerabilities)} issues found")

        # ── Phase 4: Summary ─────────────────────────────────────────────────
        task_summary = progress.add_task(
            "[4/4] Generating AI report...", total=None, detail=""
        )
        ai_summary = ""
        if not no_ai and cfg.api_key and vulnerabilities:
            import json as _json
            issues_data = [
                {"file": v.file_path, "severity": v.severity,
                 "issue": v.issue, "explanation": v.explanation}
                for v in vulnerabilities
            ]
            prompt = summary_prompt(str(root), _json.dumps(issues_data, indent=2))
            ai_summary = await call_ai(prompt, cfg.api_key, cfg.default_model, temperature=0.4)
        progress.update(task_summary, completed=100, total=100, detail="Done")

    # ── Build result ─────────────────────────────────────────────────────────
    result = LocalScanResult(
        target=str(root),
        total_files_found=len(candidates),
        files_triaged=[p.relative_to(root).as_posix() for p in triaged],
        vulnerabilities=vulnerabilities,
        ai_summary=ai_summary,
    )
    result.compute_score()

    # ── Output ───────────────────────────────────────────────────────────────
    fmt = cfg.output_format

    if fmt in ("terminal", "all"):
        print_code_scan_report(result)
    if fmt in ("json",):
        console.print(to_json(result, "code"))
    if fmt in ("markdown", "all"):
        path_out = save_markdown(result, "code")
        if not ci:
            console.print(f"  [green]✓ Markdown report saved:[/green] [dim]{path_out}[/dim]\n")
    if fmt == "json" and not ci:
        path_out = save_json(result, "code")
        console.print(f"  [green]✓ JSON report saved:[/green] [dim]{path_out}[/dim]\n")

    # ── CI exit code ─────────────────────────────────────────────────────────
    if ci:
        _ci_exit(result.vulnerabilities, fail_on, "code")
        return

    # ── Interactive REPL ─────────────────────────────────────────────────────
    if fmt in ("terminal", "all", "markdown") and not no_ai:
        ctx = ReplContext(
            target=str(root),
            scan_result=result,
            target_type="code",
            api_key=cfg.api_key,
            model=cfg.default_model,
        )
        await run_repl(ctx)


# ── web ───────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("url")
@click.option("--model",   "-m", default=None, help="Override AI model")
@click.option("--output",  "-o", default=None,
              type=click.Choice(["terminal", "json", "markdown", "all"]))
@click.option("--ci",      is_flag=True, help="CI mode — no REPL")
@click.option("--fail-on", default=None,
              type=click.Choice(["critical", "warning", "info"]))
@click.option("--no-ai",   is_flag=True, help="Skip AI summary")
def web(url, model, output, ci, fail_on, no_ai):
    """
    Scan a URL for web security issues.

    \b
    Examples:
      securelens web https://example.com
      securelens web https://my-app.com --output markdown
    """
    _run(_web_async(url, model, output, ci, fail_on, no_ai))


async def _web_async(url, model, output, ci, fail_on, no_ai):
    from securelens.config import load_config
    from securelens.output import (
        print_banner, print_scan_header, print_web_scan_report,
        make_progress, console
    )
    from securelens.output.exporters import save_json, save_markdown, to_json
    from securelens.scanners.web_scanner import scan_url
    from securelens.ai import call_ai
    from securelens.ai.prompts import web_summary_prompt
    from securelens.repl import run_repl, ReplContext
    import json as _json

    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cfg = load_config()
    if model:
        cfg.default_model = model
    if output:
        cfg.output_format = output

    if not ci:
        print_banner()
        print_scan_header(url, cfg.default_model)

    with make_progress() as progress:
        task = progress.add_task("[1/2] Running web security checks...", total=None, detail="")
        result = await scan_url(url, timeout=cfg.scan_timeout)
        progress.update(task, completed=100, total=100,
                        detail=f"{len(result.issues)} issues found")

        task2 = progress.add_task("[2/2] Generating AI summary...", total=None, detail="")
        if not no_ai and cfg.api_key and result.issues:
            issues_data = [
                {"layer": i.layer, "severity": i.severity, "issue": i.issue}
                for i in result.issues
            ]
            prompt = web_summary_prompt(url, _json.dumps(issues_data, indent=2),
                                        result.score, result.grade)
            result.ai_summary = await call_ai(prompt, cfg.api_key, cfg.default_model, temperature=0.4)
        progress.update(task2, completed=100, total=100, detail="Done")

    fmt = cfg.output_format
    if fmt in ("terminal", "all"):
        print_web_scan_report(result)
    if fmt == "json":
        console.print(to_json(result, "web"))
    if fmt in ("markdown", "all"):
        p = save_markdown(result, "web")
        if not ci:
            console.print(f"  [green]✓ Markdown saved:[/green] [dim]{p}[/dim]\n")

    if ci:
        _ci_exit(result.issues, fail_on, "web")
        return

    if fmt in ("terminal", "all", "markdown") and not no_ai:
        ctx = ReplContext(
            target=url,
            scan_result=result,
            target_type="web",
            api_key=cfg.api_key,
            model=cfg.default_model,
        )
        await run_repl(ctx)


# ── version ───────────────────────────────────────────────────────────────────

@main.command()
def version():
    """Print SecureLens AI version and config info."""
    from securelens.config import load_config, CONFIG_FILE
    from securelens import __version__

    cfg = load_config()
    console.print(f"\n  [bold cyan]SecureLens AI[/bold cyan] v{__version__}")
    console.print(f"  Model:   [dim]{cfg.default_model}[/dim]")
    console.print(f"  Config:  [dim]{CONFIG_FILE}[/dim]")
    console.print(f"  API Key: [dim]{'✓ set' if cfg.api_key else '✗ not set'}[/dim]\n")


# ── CI exit helper ─────────────────────────────────────────────────────────────

def _ci_exit(issues, fail_on, scan_type: str):
    """Exit with code 1 if issues meet or exceed the fail_on threshold."""
    severity_rank = {"critical": 4, "high": 3, "warning": 3, "medium": 2, "low": 1, "info": 0}

    if not fail_on:
        # Default: fail on any critical
        fail_on = "critical"

    threshold = severity_rank.get(fail_on, 4)
    for issue in issues:
        sev = getattr(issue, "severity", "").lower()
        if severity_rank.get(sev, 0) >= threshold:
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
