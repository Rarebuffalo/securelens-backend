"""
Terminal Renderer
=================
All Rich-based output for the CLI — banners, progress, tables, panels.
"""

import json
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.rule import Rule
from rich.syntax import Syntax
from rich.live import Live
from rich.padding import Padding

console = Console()

# ── Severity colours ──────────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "Critical": "bold red",
    "High":     "bold orange1",
    "Warning":  "bold yellow",
    "Medium":   "bold yellow",
    "Info":     "bold blue",
    "Low":      "bold cyan",
}

GRADE_COLOR = {
    "A": "bold green",
    "B": "bold cyan",
    "C": "bold yellow",
    "D": "bold orange1",
    "F": "bold red",
}


def print_banner() -> None:
    banner = Text()
    banner.append("\n")
    banner.append("  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██╗     ███████╗███╗   ██╗███████╗\n", style="bold cyan")
    banner.append("  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██║     ██╔════╝████╗  ██║██╔════╝\n", style="bold cyan")
    banner.append("  ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║     █████╗  ██╔██╗ ██║███████╗\n", style="bold blue")
    banner.append("  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║     ██╔══╝  ██║╚██╗██║╚════██║\n", style="bold blue")
    banner.append("  ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗███████╗███████╗██║ ╚████║███████║\n", style="bold magenta")
    banner.append("  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝\n", style="bold magenta")
    banner.append("                           AI Security Agent v2.0.0\n", style="dim")
    console.print(banner)


def print_scan_header(target: str, model: str) -> None:
    console.print(f"  [bold]🔍 Target:[/bold]  [cyan]{target}[/cyan]")
    console.print(f"  [bold]🧠 Model:[/bold]   [dim]{model}[/dim]")
    console.print()


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("• [dim]{task.fields[detail]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_code_scan_report(result) -> None:
    """Render a full local code scan report."""
    console.print()
    console.rule("[bold white] SECURITY REPORT [/bold white]", style="bright_black")
    console.print()

    # Score panel
    grade_color = GRADE_COLOR.get(result.grade, "white")
    score_text = Text()
    score_text.append(f"  {result.score}/100", style=f"bold {grade_color}")
    score_text.append("  Grade: ", style="dim")
    score_text.append(result.grade, style=grade_color)
    score_text.append(f"  •  {len(result.vulnerabilities)} issue(s) found", style="dim")
    score_text.append(f"  •  {len(result.files_triaged)} file(s) scanned", style="dim")
    console.print(Panel(score_text, title="[bold]Overall Score[/bold]", border_style="bright_black"))
    console.print()

    if not result.vulnerabilities:
        console.print("  [bold green]✓ No vulnerabilities found![/bold green]")
        console.print()
    else:
        _print_vulnerability_table(result.vulnerabilities)

    # AI Summary
    if result.ai_summary:
        console.print(Panel(
            result.ai_summary,
            title="[bold cyan]🤖 AI Security Summary[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))
        console.print()


def print_web_scan_report(result) -> None:
    """Render a full web scan report."""
    console.print()
    console.rule("[bold white] WEB SECURITY REPORT [/bold white]", style="bright_black")
    console.print()

    if not result.reachable:
        console.print("  [bold red]✗ Could not reach the target URL[/bold red]")
        return

    grade_color = GRADE_COLOR.get(result.grade, "white")
    score_text = Text()
    score_text.append(f"  {result.score}/100", style=f"bold {grade_color}")
    score_text.append("  Grade: ", style="dim")
    score_text.append(result.grade, style=grade_color)
    if result.ssl_expiry_days is not None:
        score_text.append(f"  •  SSL expires in {result.ssl_expiry_days} days", style="dim")
    console.print(Panel(score_text, title="[bold]Overall Score[/bold]", border_style="bright_black"))
    console.print()

    if result.exposed_paths:
        console.print(f"  [bold red]⚠ Exposed sensitive paths:[/bold red] {', '.join(result.exposed_paths)}")
        console.print()

    if not result.issues:
        console.print("  [bold green]✓ No issues found![/bold green]")
    else:
        _print_web_issue_table(result.issues)

    if result.ai_summary:
        console.print(Panel(
            result.ai_summary,
            title="[bold cyan]🤖 AI Security Summary[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))
        console.print()


def _print_vulnerability_table(vulns) -> None:
    """Render grouped vulnerability table by severity."""
    severity_order = ["Critical", "High", "Medium", "Low"]
    grouped: dict = {s: [] for s in severity_order}
    for v in vulns:
        sev = v.severity if v.severity in grouped else "Low"
        grouped[sev].append(v)

    for sev in severity_order:
        items = grouped[sev]
        if not items:
            continue
        color = SEVERITY_COLOR.get(sev, "white")
        console.print(f"  [{color}]▶ {sev.upper()} ({len(items)})[/{color}]")
        for v in items:
            loc = f"[dim]{v.file_path}"
            if v.line_number:
                loc += f":{v.line_number}"
            loc += "[/dim]"
            console.print(f"    [bold]{v.issue}[/bold]  {loc}")
            console.print(f"    [dim]{v.explanation}[/dim]")
            console.print(f"    [green]Fix:[/green] [dim]{v.suggested_fix}[/dim]")
            console.print()


def _print_web_issue_table(issues) -> None:
    """Render web scan issues grouped by layer."""
    layers: dict = {}
    for issue in issues:
        layers.setdefault(issue.layer, []).append(issue)

    for layer, items in layers.items():
        console.print(f"  [bold bright_black]── {layer} ──[/bold bright_black]")
        for item in items:
            color = SEVERITY_COLOR.get(item.severity, "white")
            console.print(f"    [{color}]●[/{color}] [bold]{item.issue}[/bold]")
            console.print(f"      [green]Fix:[/green] [dim]{item.fix}[/dim]")
        console.print()


def print_repl_prompt() -> None:
    console.print("\n[bold cyan]💬 Ask a follow-up[/bold cyan] [dim](or press Ctrl+C to exit)[/dim]")


def print_ai_response(text: str) -> None:
    console.print()
    console.print(Panel(text, border_style="dim", padding=(0, 1)))
    console.print()


def print_error(msg: str) -> None:
    console.print(f"\n  [bold red]✗ {msg}[/bold red]\n")


def print_success(msg: str) -> None:
    console.print(f"\n  [bold green]✓ {msg}[/bold green]\n")


def print_info(msg: str) -> None:
    console.print(f"  [dim]{msg}[/dim]")
