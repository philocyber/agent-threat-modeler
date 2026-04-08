"""AgenticTM CLI — Command-line interface."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="agentictm",
    help="AgenticTM -- Multi-Agent Threat Modeling System",
    add_completion=False,
)
console = Console()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False)],
    )


# ---------------------------------------------------------------------------
# CI/CD exit codes
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_CRITICAL = 1
EXIT_HIGH = 2
EXIT_MEDIUM = 3


@app.command()
def analyze(
    input_text: str = typer.Option(
        None,
        "--input",
        "-i",
        help="System description or Mermaid diagram (direct text)",
    ),
    input_file: Path = typer.Option(
        None,
        "--file",
        "-f",
        help="File with system description (.txt, .md, .mermaid)",
    ),
    system_name: str = typer.Option(
        "System",
        "--name",
        "-n",
        help="Name of the system to analyze",
    ),
    categories: str = typer.Option(
        "auto",
        "--categories",
        "--cats",
        help="Threat categories (comma-separated): auto,base,aws,azure,gcp,ai,mobile,web,iot,privacy,supply_chain",
    ),
    output_dir: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory (default: ./output/)",
    ),
    config_file: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="JSON configuration file",
    ),
    mode: str = typer.Option(
        "deep",
        "--mode",
        "-m",
        help="Scan mode: fast (~2min demo), deep (full quality ~25min), custom (user-defined model size)",
    ),
    model_size: float = typer.Option(
        None,
        "--model-size",
        "--ms",
        help="Model size in billion parameters for custom mode (e.g. 4, 8, 14, 30, 72). Only used with --mode custom.",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI/CD sidecar mode: JSON stdout, SARIF output, exit code based on severity",
    ),
    output_format: str = typer.Option(
        "both",
        "--format",
        help="Output format: csv, markdown, both, sarif, json",
    ),
    fail_on: str = typer.Option(
        "critical,high",
        "--fail-on",
        help="Severity levels that trigger non-zero exit code in CI mode (comma-separated: critical,high,medium,low)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
) -> None:
    """Run a threat modeling analysis on a system."""
    _setup_logging(verbose)
    from agentictm.config import AgenticTMConfig, LLMConfig
    from agentictm.core import AgenticTM

    if mode not in ("fast", "deep", "custom"):
        console.print(f"[red]Invalid mode: {mode}. Use: fast, deep, custom[/red]")
        raise typer.Exit(1)

    if mode == "custom" and model_size is None:
        console.print("[red]Custom mode requires --model-size (e.g. --model-size 14)[/red]")
        raise typer.Exit(1)

    # Get input
    if input_file:
        if not input_file.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)
        system_input = input_file.read_text(encoding="utf-8")
    elif input_text:
        system_input = input_text
    else:
        if ci:
            console.print("[red]CI mode requires --input or --file[/red]")
            raise typer.Exit(1)
        console.print("[yellow]Enter the system description (Ctrl+Z + Enter to finish):[/yellow]")
        system_input = sys.stdin.read()

    if not system_input.strip():
        console.print("[red]No input provided[/red]")
        raise typer.Exit(1)

    cat_list = [c.strip() for c in categories.split(",") if c.strip()]

    if not ci:
        mode_label = mode if mode != "custom" else f"custom ({model_size}B)"
        console.print(
            Panel(
                f"[bold]System:[/bold] {system_name}\n[bold]Mode:[/bold] {mode_label}\n[bold]Input:[/bold] {len(system_input)} characters\n[bold]Categories:[/bold] {', '.join(cat_list)}",
                title="AgenticTM -- Threat Modeling",
                border_style="cyan",
            )
        )

    # Load config
    config = AgenticTMConfig.load(config_file)

    # Apply scan mode overrides
    if mode == "fast":
        fast_llm = LLMConfig(
            model="qwen3:4b",
            temperature=0.3,
            timeout=120,
            think=False,
            num_predict=4096,
        )
        config.quick_thinker = fast_llm
        config.deep_thinker = fast_llm.model_copy(update={"temperature": 0.2})
        config.stride_thinker = fast_llm.model_copy()
        config.vlm.vlm_image_timeout = 60
        config.pipeline.enabled_analysts = ["stride", "attack_tree"]
        config.pipeline.skip_debate = True
        config.pipeline.skip_enriched_attack_tree = True
        config.pipeline.skip_dread_validator = True
        config.pipeline.skip_output_localizer = True
        config.pipeline.target_threats = 10
        config.pipeline.max_debate_rounds = 0
        if not ci:
            console.print("[yellow]Fast mode (~2 min): qwen3:4b, STRIDE+AttackTree, no debate, VLM 60s[/yellow]")
    elif mode == "custom" and model_size is not None:
        from agentictm.api.server import _resolve_ollama_model

        model_name = _resolve_ollama_model(model_size)
        custom_llm = LLMConfig(
            model=model_name,
            temperature=0.2,
            timeout=900,
            num_gpu=-1,
            think=model_size >= 14,
        )
        config.deep_thinker = custom_llm
        config.stride_thinker = custom_llm.model_copy(update={"temperature": 0.3})
        if model_size >= 30:
            config.quick_thinker = custom_llm.model_copy(update={"think": False, "temperature": 0.3})
        if not ci:
            console.print(f"[blue]Custom mode: model={model_name} ({model_size}B params)[/blue]")

    tm = AgenticTM(config)

    # Run analysis
    if ci:
        result = tm.analyze(system_input, system_name, threat_categories=cat_list)
    else:
        with console.status("[bold cyan]Running multi-agent analysis..."):
            result = tm.analyze(system_input, system_name, threat_categories=cat_list)

    threats = result.get("threats_final", [])

    # ── CI/CD Mode: structured output + exit codes ──
    if ci:
        ci_output = _build_ci_output(result, system_name, output_format)
        print(json.dumps(ci_output, indent=2))

        # Save SARIF if requested
        if output_format == "sarif" or output_format == "json":
            out_path = tm.save_output(result, output_dir)
            try:
                from agentictm.agents.report_generator import generate_sarif
                sarif_content = generate_sarif(result)
                sarif_path = out_path / "threat_model.sarif"
                sarif_path.write_text(sarif_content, encoding="utf-8")
            except Exception:
                pass

        # Exit code based on severity
        fail_levels = {s.strip().lower() for s in fail_on.split(",") if s.strip()}
        exit_code = _ci_exit_code(threats, fail_levels)
        raise typer.Exit(exit_code)

    # ── Interactive Mode: pretty table ──
    if threats:
        table = Table(title=f"Threat Model — {system_name}", show_lines=True)
        table.add_column("ID", style="bold")
        table.add_column("Component")
        table.add_column("Threat", max_width=50)
        table.add_column("DREAD", justify="center")
        table.add_column("Priority", justify="center")

        for t in threats[:15]:
            prio = t.get("priority", "?")
            prio_style = {
                "Critical": "bold red",
                "High": "red",
                "Medium": "yellow",
                "Low": "green",
            }.get(prio, "")

            table.add_row(
                t.get("id", "?"),
                t.get("component", "?"),
                t.get("description", "?")[:50],
                str(t.get("dread_total", 0)),
                f"[{prio_style}]{prio}[/{prio_style}]" if prio_style else prio,
            )

        console.print(table)
        if len(threats) > 15:
            console.print(f"  ... and {len(threats) - 15} more threats")
    else:
        console.print("[yellow]No threats were generated[/yellow]")

    # Save output
    out_path = tm.save_output(result, output_dir)
    console.print(f"\n[green]Output saved to: {out_path}[/green]")


def _build_ci_output(result: dict, system_name: str, output_format: str) -> dict:
    """Build structured JSON output for CI/CD pipelines."""
    threats = result.get("threats_final", [])
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        prio = t.get("priority", "Low")
        if prio in severity_counts:
            severity_counts[prio] += 1

    output = {
        "system_name": system_name,
        "threat_count": len(threats),
        "severity_counts": severity_counts,
        "stride_coverage": list({t.get("stride_category", "") for t in threats if t.get("stride_category")}),
        "threats": [
            {
                "id": t.get("id", ""),
                "description": t.get("description", ""),
                "component": t.get("component", ""),
                "stride_category": t.get("stride_category", ""),
                "priority": t.get("priority", ""),
                "dread_total": t.get("dread_total", 0),
                "mitigation": t.get("mitigation", ""),
            }
            for t in threats
        ],
    }

    if output_format == "sarif":
        try:
            from agentictm.agents.report_generator import generate_sarif
            output["sarif"] = json.loads(generate_sarif(result))
        except Exception:
            pass

    return output


def _ci_exit_code(threats: list, fail_levels: set[str]) -> int:
    """Determine CI exit code based on threat severities."""
    for t in threats:
        prio = (t.get("priority") or "").lower()
        if prio in fail_levels:
            if prio == "critical":
                return EXIT_CRITICAL
            elif prio == "high":
                return EXIT_HIGH
            elif prio == "medium":
                return EXIT_MEDIUM
    return EXIT_OK


@app.command()
def index(
    knowledge_base: Path = typer.Option(
        Path("./rag"),
        "--path",
        "-p",
        help="Path to rag/ directory",
    ),
    config_file: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="JSON configuration file",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Index RAG source documents."""
    _setup_logging(verbose)
    from agentictm.config import AgenticTMConfig
    from agentictm.core import AgenticTM

    config = AgenticTMConfig.load(config_file)
    config.rag.knowledge_base_path = knowledge_base
    tm = AgenticTM(config)

    console.print(
        Panel(
            f"[bold]RAG Sources:[/bold] {knowledge_base}",
            title="AgenticTM -- RAG Indexing",
            border_style="cyan",
        )
    )

    with console.status("[bold cyan]Indexing documents..."):
        results = tm.index_knowledge_base()

    table = Table(title="Indexing Results")
    table.add_column("Store", style="bold")
    table.add_column("Chunks", justify="right")

    total = 0
    for store_name, count in results.items():
        table.add_row(store_name, str(count))
        total += count

    table.add_row("[bold]TOTAL[/bold]", f"[bold]{total}[/bold]")
    console.print(table)


@app.command()
def init(
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Path to create the project structure",
    ),
) -> None:
    """Initialize the project directory structure."""
    dirs = [
        path / "rag" / "books",
        path / "rag" / "research",
        path / "rag" / "risks_mitigations",
        path / "rag" / "previous_threat_models",
        path / "rag" / "ai_threats",
        path / "data" / "vector_stores",
        path / "output",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        gitkeep = d / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.touch()

    console.print("[green]Directory structure created:[/green]")
    for d in dirs:
        console.print(f"  {d}")

    from agentictm.config import AgenticTMConfig

    config_path = path / "config.json"
    if not config_path.exists():
        AgenticTMConfig().save(config_path)
        console.print(f"  {config_path}")

    console.print("\n[cyan]Next steps:[/cyan]")
    console.print("  1. Add PDFs to rag/books/")
    console.print("  2. Add papers to rag/research/")
    console.print("  3. Add CAPEC/CWE/NIST to rag/risks_mitigations/")
    console.print("  4. Add previous TMs (.csv) to rag/previous_threat_models/")
    console.print("  5. Add PLOT4ai deck.json to rag/ai_threats/")
    console.print("  6. Run: [bold]agentictm index[/bold]")
    console.print("  7. Run: [bold]agentictm analyze -n 'My System' -f description.md[/bold]")
    console.print("  8. For AWS projects: [bold]agentictm analyze --cats aws,ai -f desc.md[/bold]")


if __name__ == "__main__":
    app()
