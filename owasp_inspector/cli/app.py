from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from owasp_inspector import __version__
from owasp_inspector.cli.history import ScanHistoryStore
from owasp_inspector.core.exceptions import AuthorizationError, OwaspInspectorError
from owasp_inspector.core.orchestrator import run_scan
from owasp_inspector.core.profiles import DEFAULT_PROFILE, PROFILES
from owasp_inspector.reporting.builder import build_report
from owasp_inspector.reporting.renderers.html_renderer import render_html
from owasp_inspector.reporting.renderers.json_renderer import render_json
from owasp_inspector.reporting.renderers.markdown_renderer import render_markdown
from owasp_inspector.reporting.renderers.pdf_renderer import render_pdf
from owasp_inspector.safety.authorization import confirm_authorization

app = typer.Typer(
    add_completion=False,
    help="OWASP Inspector — automated OWASP Top 10 assessment engine. Give it a URL; it does the rest.",
)
console = Console()

# (file extension, render function, is_binary_output)
_RENDERERS = {
    "json": ("json", render_json, False),
    "markdown": ("md", render_markdown, False),
    "html": ("html", render_html, False),
    "pdf": ("pdf", render_pdf, True),
}

_KNOWN_COMMANDS = {"scan", "history"}


def _validate_profile(value: str) -> str:
    if value not in PROFILES:
        raise typer.BadParameter(f"Unknown profile {value!r}. Valid: {', '.join(sorted(PROFILES))}")
    return value


def _validate_formats(value: str) -> list[str]:
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    for fmt in formats:
        if fmt not in _RENDERERS:
            raise typer.BadParameter(f"Unknown format {fmt!r}. Valid: {', '.join(_RENDERERS)}")
    return formats or ["html", "json"]


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to assess. Only scan systems you own or are authorized to test."),
    profile: str = typer.Option(
        DEFAULT_PROFILE, "--profile", "-p", help=f"Scan profile: {', '.join(sorted(PROFILES))}"
    ),
    max_pages: int = typer.Option(40, "--max-pages", help="Maximum pages to crawl during discovery."),
    formats: str = typer.Option(
        "html,json", "--format", "-f", help="Comma-separated report formats: json, markdown, html, pdf"
    ),
    output_dir: Path = typer.Option(
        Path("Data") / "reports", "--output-dir", "-o", help="Directory to write reports into."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the interactive authorization prompt (same as OWASP_INSPECTOR_AUTHORIZED=1)."
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="Reuse the cached discovery result for this URL instead of re-crawling, if one completed within the last hour.",
    ),
    respect_robots: bool = typer.Option(
        False,
        "--respect-robots",
        help="Honor robots.txt Disallow rules during the crawl. Off by default: robots.txt is a crawler-politeness convention, not access control, and this only runs after you've confirmed authorization.",
    ),
):
    """Run a fully automated OWASP Top 10 assessment against URL and write reports.

    This is the one command this whole engine is built around: give it a URL
    (`owasp-inspector https://target.com` works directly — `scan` is implied),
    it discovers the target and runs every applicable assessment module
    automatically. No scanner selection, no manual workflow.
    """
    profile = _validate_profile(profile)
    requested_formats = _validate_formats(formats)

    if yes:
        os.environ["OWASP_INSPECTOR_AUTHORIZED"] = "1"

    try:
        confirm_authorization(url, interactive=not yes)
    except AuthorizationError as exc:
        console.print(f"[bold red]Authorization not confirmed:[/bold red] {exc}")
        raise typer.Exit(code=1) from None

    console.print(f"[bold]OWASP Inspector[/bold] v{__version__} — scanning [cyan]{url}[/cyan] (profile: {profile})")

    with console.status("Running discovery and assessment modules...", spinner="dots"):
        try:
            result = asyncio.run(
                run_scan(url, profile=profile, max_pages=max_pages, resume=resume, respect_robots=respect_robots)
            )
        except OwaspInspectorError as exc:
            console.print(f"[bold red]Scan failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from None
        except Exception as exc:
            console.print(f"[bold red]Scan failed unexpectedly:[/bold red] {exc}")
            raise typer.Exit(code=1) from None

    report = build_report(result)
    _print_summary(report)

    output_dir.mkdir(parents=True, exist_ok=True)
    written_paths: list[str] = []
    for fmt in requested_formats:
        ext, renderer, is_binary = _RENDERERS[fmt]
        out_path = output_dir / f"{report.scan_id}.{ext}"
        content = renderer(report)
        if is_binary:
            out_path.write_bytes(content)
        else:
            out_path.write_text(content, encoding="utf-8")
        written_paths.append(str(out_path))
        console.print(f"  [green]OK[/green] {fmt} report -> [bold]{out_path}[/bold]")

    ScanHistoryStore().append(report, written_paths)

    if report.risk.grade in ("D", "F"):
        raise typer.Exit(code=2)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum number of past scans to show, most recent first."),
):
    """List past scans recorded in local history."""
    entries = ScanHistoryStore().list_all()
    if not entries:
        console.print("No scan history yet — run `owasp-inspector <url>` first.")
        return

    table = Table(title="Scan History")
    table.add_column("Scan ID")
    table.add_column("Target")
    table.add_column("Grade")
    table.add_column("Score")
    table.add_column("Findings", justify="right")
    table.add_column("Generated")
    for entry in entries[-limit:][::-1]:
        table.add_row(
            entry.scan_id, entry.final_url, entry.grade, str(entry.score), str(entry.finding_count), entry.generated_at
        )
    console.print(table)


def _print_summary(report) -> None:
    table = Table(title="Findings by Severity")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for severity, count in report.risk.severity_counts.items():
        if count:
            table.add_row(severity, str(count))
    console.print(table)
    console.print(f"Overall grade: [bold]{report.risk.grade}[/bold] ({report.risk.score}/100)")
    console.print(report.executive_summary)


def _configure_utf8_stdio() -> None:
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def rewrite_argv_for_implicit_scan(args: list[str]) -> list[str]:
    """`owasp-inspector <url> [options]` (no explicit `scan` keyword) becomes
    `scan <url> [options]` before Typer parses it — Click's Group parsing
    doesn't support a positional argument ahead of subcommand dispatch, so
    without this, options would only be accepted before the URL, not after.
    This restores normal option ordering on top of Click's model instead of
    documenting around the limitation. Pulled out as a pure function so the
    rewriting logic is testable without invoking the CLI.
    """
    if args and args[0] not in _KNOWN_COMMANDS and args[0] not in ("--help", "-h"):
        return ["scan", *args]
    return args


def main():
    _configure_utf8_stdio()
    args = sys.argv[1:]
    if args and args[0] in ("--version", "-V"):
        console.print(f"owasp-inspector {__version__}")
        raise SystemExit(0)
    sys.argv = [sys.argv[0], *rewrite_argv_for_implicit_scan(args)]
    app()


if __name__ == "__main__":
    main()
