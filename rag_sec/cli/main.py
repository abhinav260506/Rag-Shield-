import sys
import argparse
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from rag_sec.core.models import TargetConfig, TargetType, Severity
from rag_sec.core.connector import LocalPythonRAGConnector, HTTPRAGConnector, LangChainConnector, LlamaIndexConnector
from rag_sec.core.runner import SecurityRunner
from examples.mock_rag_target import get_mock_rag_target

console = Console()

def run_scan_command(args):
    console.print(Panel.fit("[bold cyan]RAG Security Scanner & Evaluation Suite (rag-sec)[/bold cyan]\n[dim]Auditing RAG Pipeline against OWASP Top 10 for LLM Applications[/dim]", border_style="cyan"))

    if args.mock:
        console.print(f"[yellow]Initializing Mock RAG Target (Guarded: {args.guarded})...[/yellow]")
        mock_app = get_mock_rag_target(security_enabled=args.guarded)
        config = TargetConfig(name="Mock RAG Pipeline", target_type=TargetType.LOCAL_PYTHON)
        connector = LocalPythonRAGConnector(config=config, query_fn=mock_app.query, ingest_fn=mock_app.ingest)
    elif args.url:
        console.print(f"[yellow]Connecting to HTTP Endpoint Target: {args.url}...[/yellow]")
        config = TargetConfig(name=args.name or "HTTP RAG Target", target_type=TargetType.HTTP_ENDPOINT, endpoint_url=args.url)
        connector = HTTPRAGConnector(config=config)
    else:
        console.print("[bold red]Error:[/bold red] Please specify either --mock (for sample target) or --url <ENDPOINT_URL>")
        sys.exit(1)

    runner = SecurityRunner(connector)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Running Security Evaluators...", total=None)
        report = runner.execute_scan()

    # Print Summary Panel
    severity_color = "green" if report.risk_score < 3.0 else ("yellow" if report.risk_score < 7.0 else "red")
    console.print(f"\n[bold]Scan ID:[/bold] {report.scan_id}")
    console.print(f"[bold]Target Name:[/bold] {report.target_name}")
    console.print(f"[bold]Risk Score:[/bold] [{severity_color}]{report.risk_score} / 10.0[/{severity_color}]")
    console.print(f"[bold]Total Findings:[/bold] {report.total_findings}\n")

    # Table of Findings
    table = Table(title="Security Findings Summary", border_style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Title")
    table.add_column("OWASP Benchmark")

    for res in report.evaluator_results:
        for finding in res.findings:
            sev_style = "red" if finding.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow"
            table.add_row(
                f"[{sev_style}]{finding.severity.value}[/{sev_style}]",
                finding.category.value,
                finding.title,
                finding.owasp_mapping
            )

    console.print(table)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report.model_dump_json(indent=2))
        console.print(f"\n[green]Scan report saved to {args.output}[/green]")

def main():
    parser = argparse.ArgumentParser(description="rag-sec: RAG Security Scanner & Evaluation Suite")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run security audit scan on a RAG target")
    scan_parser.add_argument("--mock", action="store_true", help="Use built-in mock target pipeline")
    scan_parser.add_argument("--guarded", action="store_true", help="Enable security guardrails on mock target")
    scan_parser.add_argument("--url", type=str, help="HTTP URL endpoint of RAG target")
    scan_parser.add_argument("--config", type=str, help="JSON configuration file containing target details")
    scan_parser.add_argument("--name", type=str, help="Target application name")
    scan_parser.add_argument("--output", type=str, help="Output JSON file path for report")

    args = parser.parse_args()
    if args.command == "scan":
        run_scan_command(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
