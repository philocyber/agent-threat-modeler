"""AgenticTM CLI — Interface de línea de comandos."""

from __future__ import annotations

import logging
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


@app.command()
def analyze(
    input_text: str = typer.Option(
        None,
        "--input",
        "-i",
        help="Descripción del sistema o diagrama Mermaid (texto directo)",
    ),
    input_file: Path = typer.Option(
        None,
        "--file",
        "-f",
        help="Archivo con la descripción del sistema (.txt, .md, .mermaid)",
    ),
    system_name: str = typer.Option(
        "System",
        "--name",
        "-n",
        help="Nombre del sistema a analizar",
    ),
    categories: str = typer.Option(
        "auto",
        "--categories",
        "--cats",
        help="Categorías de amenazas (comma-separated): auto,base,aws,azure,gcp,ai,mobile,web,iot,privacy,supply_chain",
    ),
    output_dir: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Directorio de output (default: ./output/)",
    ),
    config_file: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="Archivo de configuración JSON",
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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
) -> None:
    """Run a threat modeling analysis on a system."""
    _setup_logging(verbose)
    from agentictm.config import AgenticTMConfig, LLMConfig
    from agentictm.core import AgenticTM

    # Validate mode
    if mode not in ("fast", "deep", "custom"):
        console.print(f"[red]❌ Modo inválido: {mode}. Usa: fast, deep, custom[/red]")
        raise typer.Exit(1)

    if mode == "custom" and model_size is None:
        console.print("[red]❌ Modo 'custom' requiere --model-size (ej: --model-size 14)[/red]")
        raise typer.Exit(1)

    # Obtener el input
    if input_file:
        if not input_file.exists():
            console.print(f"[red]❌ Archivo no encontrado: {input_file}[/red]")
            raise typer.Exit(1)
        system_input = input_file.read_text(encoding="utf-8")
    elif input_text:
        system_input = input_text
    else:
        console.print("[yellow]Ingresá la descripción del sistema (Ctrl+Z + Enter para terminar):[/yellow]")
        import sys

        system_input = sys.stdin.read()

    if not system_input.strip():
        console.print("[red]❌ No se proporcionó input[/red]")
        raise typer.Exit(1)

    # Parse categories
    cat_list = [c.strip() for c in categories.split(",") if c.strip()]

    mode_label = mode if mode != "custom" else f"custom ({model_size}B)"
    console.print(
        Panel(
            f"[bold]Sistema:[/bold] {system_name}\n[bold]Modo:[/bold] {mode_label}\n[bold]Input:[/bold] {len(system_input)} caracteres\n[bold]Categorías:[/bold] {', '.join(cat_list)}",
            title="AgenticTM -- Threat Modeling",
            border_style="cyan",
        )
    )

    # Cargar config e inicializar
    config = AgenticTMConfig.load(config_file)

    # ── Apply scan mode overrides ──────────────────────────────────
    if mode == "fast":
        fast_llm = LLMConfig(
            model="qwen3.5:4b",
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
        console.print("[yellow]⚡ Fast mode (~2 min): qwen3.5:4b, STRIDE+AttackTree, sin debate, VLM 60s[/yellow]")
    elif mode == "custom" and model_size is not None:
        # Resolve closest Ollama model
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
        console.print(f"[blue]🔧 Custom mode: modelo={model_name} ({model_size}B params)[/blue]")

    tm = AgenticTM(config)

    # Ejecutar análisis
    with console.status("[bold cyan]Ejecutando análisis multi-agente..."):
        result = tm.analyze(system_input, system_name, threat_categories=cat_list)

    # Mostrar resumen
    threats = result.get("threats_final", [])
    if threats:
        table = Table(title=f"Threat Model — {system_name}", show_lines=True)
        table.add_column("ID", style="bold")
        table.add_column("Component")
        table.add_column("Threat", max_width=50)
        table.add_column("DREAD", justify="center")
        table.add_column("Priority", justify="center")

        for t in threats[:15]:  # Máx 15 en pantalla
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
            console.print(f"  ... y {len(threats) - 15} amenazas más")
    else:
        console.print("[yellow]No threats were generated[/yellow]")

    # Guardar output
    out_path = tm.save_output(result, output_dir)
    console.print(f"\n[green]Output saved to: {out_path}[/green]")


@app.command()
def index(
    knowledge_base: Path = typer.Option(
        Path("./knowledge_base"),
        "--path",
        "-p",
        help="Path al directorio knowledge_base/",
    ),
    config_file: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="Archivo de configuración JSON",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Index knowledge base documents into RAG."""
    _setup_logging(verbose)
    from agentictm.config import AgenticTMConfig
    from agentictm.core import AgenticTM

    config = AgenticTMConfig.load(config_file)
    config.rag.knowledge_base_path = knowledge_base
    tm = AgenticTM(config)

    console.print(
        Panel(
            f"[bold]Knowledge Base:[/bold] {knowledge_base}",
            title="AgenticTM -- RAG Indexing",
            border_style="cyan",
        )
    )

    with console.status("[bold cyan]Indexando documentos..."):
        results = tm.index_knowledge_base()

    table = Table(title="Resultados de Indexación")
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
        help="Path donde crear la estructura del proyecto",
    ),
) -> None:
    """Initialize the project directory structure."""
    dirs = [
        path / "knowledge_base" / "books",
        path / "knowledge_base" / "research",
        path / "knowledge_base" / "risks_mitigations",
        path / "knowledge_base" / "previous_threat_models",
        path / "knowledge_base" / "ai_threats",
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

    # Crear config default
    from agentictm.config import AgenticTMConfig

    config_path = path / "config.json"
    if not config_path.exists():
        AgenticTMConfig().save(config_path)
        console.print(f"  {config_path}")

    console.print("\n[cyan]Próximos pasos:[/cyan]")
    console.print("  1. Agregá PDFs a knowledge_base/books/")
    console.print("  2. Agregá papers a knowledge_base/research/")
    console.print("  3. Agregá CAPEC/CWE/NIST a knowledge_base/risks_mitigations/")
    console.print("  4. Agregá TMs previos (.csv) a knowledge_base/previous_threat_models/")
    console.print("  5. Agregá deck.json de PLOT4ai a knowledge_base/ai_threats/")
    console.print("  6. Ejecutá: [bold]agentictm index[/bold]")
    console.print("  7. Ejecutá: [bold]agentictm analyze -n 'Mi Sistema' -f descripcion.md[/bold]")
    console.print("  8. Para proyectos AWS: [bold]agentictm analyze --cats aws,ai -f desc.md[/bold]")


if __name__ == "__main__":
    app()
