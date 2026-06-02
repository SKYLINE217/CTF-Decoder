import click
import sys
import os

from ctf_decoder.core.request import DecodeRequest
from ctf_decoder.core.pipeline import PipelineManager
from ctf_decoder.registry import registry
from ctf_decoder.detection.engine import DetectionEngine
from ctf_decoder.output.formatter import evaluate_and_display
from ctf_decoder.output.flag_detector import FlagDetector
import ctf_decoder.decoders  # Ensure all built-ins are registered
from ctf_decoder.plugins.loader import load_plugins

# Initialize plugins
load_plugins()

@click.group()
def cli():
    """CTF Decoder - A modular decoding suite."""
    pass

@cli.command()
def list():
    """List all available codecs."""
    codecs = registry.all_codecs()
    click.echo(f"Available codecs ({len(codecs)}):")
    for codec in sorted(codecs, key=lambda c: c.name):
        aliases = f" (aliases: {', '.join(codec.aliases)})" if codec.aliases else ""
        click.echo(f"  - {codec.name}{aliases}: {codec.description}")

@cli.command()
@click.argument('input_text', required=False)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='Read input from file')
@click.option('--json', 'as_json', is_flag=True, help='Output results as JSON')
def detect(input_text, file, as_json):
    """Run auto-detection on input data (no decoding)."""
    from rich.table import Table
    from rich.console import Console
    from rich import box as rbox
    data = _get_input_data(input_text, file)
    if not data:
        click.echo("Error: No input provided.")
        sys.exit(1)

    engine = DetectionEngine()
    try:
        candidates = engine.detect(data)
    except Exception as e:
        click.echo(f"Error during detection: {e}", err=True)
        sys.exit(1)

    if not candidates:
        click.echo("No encodings detected.")
        sys.exit(1)

    if as_json:
        import json
        print(json.dumps([{"codec": n, "confidence": round(s, 4)} for s, n in candidates], indent=2))
    else:
        con = Console()
        table = Table(title="Detection Results", box=rbox.SIMPLE_HEAVY, header_style="bold cyan")
        table.add_column("Rank", style="dim", width=6)
        table.add_column("Codec", style="bold")
        table.add_column("Confidence", justify="right")
        for i, (score, name) in enumerate(candidates, 1):
            bar = "█" * int(score * 20)
            table.add_row(str(i), name, f"{score*100:5.1f}%  {bar}")
        con.print(table)

@cli.command()
@click.argument('input_text', required=False)
@click.option('-c', '--codec', help='Specific codec to use')
@click.option('--chain', help='Comma-separated list of codecs to apply in order')
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='Read input from file')
@click.option('-o', '--output', type=click.Path(dir_okay=False), help='Write raw output bytes to file')
@click.option('--json', 'as_json', is_flag=True, help='Output results as JSON')
@click.option('-v', '--verbose', is_flag=True, help='Show decode steps and plaintext score')
@click.option('--flag-pattern', 'flag_pattern', default=None, help='Extra regex pattern for flag detection')
def decode(input_text, codec, chain, file, output, as_json, verbose, flag_pattern):
    """Decode input data (auto-detect or specify --codec / --chain)."""
    data = _get_input_data(input_text, file)
    if not data:
        click.echo("Error: No input provided.")
        sys.exit(1)

    pipeline = PipelineManager()

    if chain:
        chain_list = [c.strip() for c in chain.split(",")]
        request = DecodeRequest(input_bytes=data, chain=chain_list)
        result = pipeline.run_chain(request)
    else:
        request = DecodeRequest(input_bytes=data, target_codec=codec)
        result = pipeline.run_single(request)

    # Write raw bytes to file if requested
    if output and result.success and result.final_output:
        with open(output, "wb") as f:
            f.write(result.final_output)
        click.echo(f"Output written to {output}")
        return

    extra_patterns = [flag_pattern] if flag_pattern else None
    evaluate_and_display(result, as_json=as_json, verbose=verbose, flag_patterns=extra_patterns)

    if not result.success:
        sys.exit(1)

@cli.command()
@click.argument('input_text', required=False)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='Read input from file')
@click.option('--depth', default=3, help='Maximum chain depth to search')
@click.option('--timeout', default=10.0, help='Search timeout in seconds')
@click.option('--flag-pattern', 'flag_pattern', default=None, help='Extra regex pattern for flag detection')
@click.option('--json', 'as_json', is_flag=True, help='Output results as JSON')
@click.option('-v', '--verbose', is_flag=True, help='Show decode steps and plaintext score')
def brute(input_text, file, depth, timeout, flag_pattern, as_json, verbose):
    """Attempt to solve by brute-forcing decoder chains."""
    from ctf_decoder.core.bruteforce import BruteForceEngine
    data = _get_input_data(input_text, file)
    if not data:
        click.echo("Error: No input provided.")
        sys.exit(1)

    extra_patterns = [flag_pattern] if flag_pattern else None
    engine = BruteForceEngine(max_depth=depth, timeout_sec=timeout, flag_patterns=extra_patterns)
    
    click.echo(f"Starting brute-force search (max_depth={depth}, timeout={timeout}s)...", err=True)
    result = engine.search(data)
    
    if not result:
        click.echo("Brute-force failed: no flag found within depth and timeout.", err=True)
        sys.exit(1)
        
    evaluate_and_display(result, as_json=as_json, verbose=verbose, flag_patterns=extra_patterns)

@cli.command(name='autopilot')
@click.argument('input_text', required=False)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='Read input from file')
@click.option('--depth', default=5, help='Maximum recursion depth for AI search')
@click.option('--json', 'as_json', is_flag=True, help='Output results as JSON')
@click.option('-v', '--verbose', is_flag=True, help='Show decode steps and plaintext score')
@click.option('--flag-pattern', 'flag_pattern', default=None, help='Extra regex pattern for flag detection')
def autopilot(input_text, file, depth, as_json, verbose, flag_pattern):
    """Smart AI-guided autopilot decoding."""
    data = _get_input_data(input_text, file)
    if not data:
        click.echo("Error: No input provided.")
        sys.exit(1)

    pipeline = PipelineManager()
    request = DecodeRequest(input_bytes=data)
    
    click.echo(f"Starting AI-guided autopilot search (max_depth={depth})...", err=True)
    result = pipeline.run_autopilot(request, max_depth=depth)
    
    extra_patterns = [flag_pattern] if flag_pattern else None
    evaluate_and_display(result, as_json=as_json, verbose=verbose, flag_patterns=extra_patterns)

    if not result.success:
        sys.exit(1)

@cli.command(name='solve')
@click.argument('input_text', required=False)
@click.option('-f', '--file', type=click.Path(exists=True, dir_okay=False), help='Read challenge payload from file')
@click.option('--flag-pattern', 'flag_pattern', default=None, help='Extra regex pattern for flag detection')
@click.option('--json', 'as_json', is_flag=True, help='Output solves as JSON')
@click.option('-v', '--verbose', is_flag=True, help='Show scanned candidates and decode details')
def solve(input_text, file, flag_pattern, as_json, verbose):
    """Scan and solve complex multi-layered CTF challenges."""
    data_bytes = _get_input_data(input_text, file)
    if not data_bytes:
        click.echo("Error: No input provided.")
        sys.exit(1)
        
    try:
        text = data_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        click.echo(f"Error decoding input text: {e}", err=True)
        sys.exit(1)
        
    from ctf_decoder.core.solver import ChallengeSolver
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box as rbox
    
    con = Console()
    solver = ChallengeSolver()
    
    extra_patterns = [flag_pattern] if flag_pattern else None
    
    if not as_json:
        con.print(f"[*] Scanning challenge payload for potential encodings...", style="cyan")
        
    solves = solver.solve(text, extra_flag_patterns=extra_patterns)
    
    if as_json:
        import json
        out_list = []
        for s in solves:
            steps = [{"codec": step.codec, "output": step.output.decode("utf-8", errors="replace")} for step in s.result.steps]
            out_list.append({
                "candidate": {
                    "match": s.candidate.raw_match,
                    "type": s.candidate.match_type,
                    "start": s.candidate.start,
                    "end": s.candidate.end
                },
                "steps": steps,
                "flag": s.flag
            })
        print(json.dumps(out_list, indent=2))
        return
        
    if not solves:
        con.print("[bold red][!] No CTF flags resolved from scanned candidates.[/bold red]")
        sys.exit(1)
        
    con.print(f"[bold green][✔] Found {len(solves)} resolved flag(s)![/bold green]\n")
    
    for i, s in enumerate(solves, 1):
        con.print(Panel(
            f"[bold yellow]Candidate #{i}[/bold yellow] (Type: [cyan]{s.candidate.match_type}[/cyan] at [{s.candidate.start}:{s.candidate.end}])\n"
            f"Raw Match: [dim]{s.candidate.raw_match[:100] + ('...' if len(s.candidate.raw_match) > 100 else '')}[/dim]\n\n"
            f"[bold green]Decoded Flag:[/bold green] [bold white on dark_red] {s.flag} [/bold white on dark_red]",
            title=f"Solve #{i}",
            border_style="green",
            expand=False
        ))
        
        if verbose or len(s.result.steps) > 1:
            chain_table = Table(title="Decode Chain", box=rbox.SIMPLE_HEAVY, header_style="bold cyan")
            chain_table.add_column("#", style="dim", width=4)
            chain_table.add_column("Codec", style="bold")
            chain_table.add_column("Output")
            
            for step_idx, step in enumerate(s.result.steps, 1):
                display = step.output.decode("utf-8", errors="replace")
                if len(display) > 80:
                    display = display[:77] + "..."
                chain_table.add_row(str(step_idx), step.codec, display)
                
            con.print(chain_table)
            con.print()

@cli.command()
@click.argument('codec')
@click.option('--platform', default=None, help='CTF platform (e.g. picoCTF, HTB)')
def confirm(codec, platform):
    """Record explicit positive feedback that a codec succeeded."""
    from ctf_decoder.adaptive.memory import memory_db, session, build_solve_event
    decoder = registry.get(codec)
    if not decoder:
        click.echo(f"Unknown codec: {codec}", err=True)
        sys.exit(1)
    memory_db.update_prior(decoder.name, was_correct=True)
    memory_db.upsert_chain_template([decoder.name], platform=platform, success=True)
    if platform:
        memory_db.update_platform_profile(platform, [decoder.name])
    prior = memory_db.get_prior(decoder.name)
    click.echo(f"[+] Positive feedback recorded for '{decoder.name}'. "
               f"Prior: alpha={prior.alpha:.2f}, beta={prior.beta:.2f}")


@cli.command()
@click.argument('codec')
def reject(codec):
    """Record explicit negative feedback that a codec failed."""
    from ctf_decoder.adaptive.memory import memory_db
    decoder = registry.get(codec)
    if not decoder:
        click.echo(f"Unknown codec: {codec}", err=True)
        sys.exit(1)
    memory_db.update_prior(decoder.name, was_correct=False)
    prior = memory_db.get_prior(decoder.name)
    click.echo(f"[-] Negative feedback recorded for '{decoder.name}'. "
               f"Prior: alpha={prior.alpha:.2f}, beta={prior.beta:.2f}")


@cli.group()
def memory():
    """Manage the adaptive engine memory store."""
    pass


@memory.command(name='status')
def memory_status():
    """Show learned priors and session summary."""
    from ctf_decoder.adaptive.memory import memory_db, session
    from rich.console import Console
    from rich.table import Table
    from rich import box as rbox

    con = Console(highlight=False)
    con.print(f"\n[bold cyan]Session:[/bold cyan] {session.summary()}\n")

    priors = memory_db.get_all_priors()
    if not priors:
        con.print("[dim]No learned priors yet.[/dim]")
        return

    t = Table(title="Learned Codec Priors", box=rbox.SIMPLE_HEAVY, header_style="bold cyan")
    t.add_column("Codec", style="bold")
    t.add_column("Success Rate", justify="right")
    t.add_column("Alpha", justify="right")
    t.add_column("Beta", justify="right")
    t.add_column("Last Updated")

    for codec, p in sorted(priors, key=lambda x: -x[1].expected_value):
        t.add_row(
            codec,
            f"{p.expected_value:.1%}",
            f"{p.alpha:.2f}",
            f"{p.beta:.2f}",
            p.last_updated[:10],
        )
    con.print(t)

    templates = memory_db.get_chain_templates()
    if templates:
        ct = Table(title="Chain Templates", box=rbox.SIMPLE_HEAVY, header_style="bold magenta")
        ct.add_column("Chain")
        ct.add_column("Freq", justify="right")
        ct.add_column("Success Rate", justify="right")
        ct.add_column("Platform")
        for tmpl in templates[:10]:
            ct.add_row(
                " > ".join(tmpl.chain),
                str(tmpl.frequency),
                f"{tmpl.success_rate:.0%}",
                tmpl.platform or "-",
            )
        con.print(ct)


@memory.command(name='decay')
def memory_decay():
    """Apply time-based confidence decay to all codec priors."""
    from ctf_decoder.adaptive.memory import memory_db
    memory_db.apply_decay()
    click.echo("[+] Decay applied. Stale priors have been pulled back toward uniform.")


@memory.command(name='clear')
@click.option('--confirm', 'do_confirm', is_flag=True, help='Required to confirm deletion')
def memory_clear(do_confirm):
    """Wipe all adaptive memory (priors, events, templates, profiles)."""
    if not do_confirm:
        click.echo("Pass --confirm to wipe all adaptive memory.")
        return
    from ctf_decoder.adaptive.memory import memory_db
    memory_db.clear()
    click.echo("[!] All adaptive memory cleared. Tool reverts to static behaviour.")

def _get_input_data(input_text, file_path) -> bytes:
    if file_path:
        with open(file_path, 'rb') as f:
            return f.read()
    elif input_text:
        return input_text.encode('utf-8')
    elif not sys.stdin.isatty():
        return sys.stdin.read().encode('utf-8')
    return b""


@cli.command(name='train-ml')
@click.option('--samples', default=50000, help='Number of synthetic samples to generate')
@click.option('--estimators', default=300, help='Number of trees in the Random Forest / Extra Trees')
def train_ml(samples, estimators):
    """Generate a large CTF dataset and train the ML detection model."""
    import time
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich import box as rbox
    
    from ctf_decoder.detection.ml_dataset import generate_dataset
    from ctf_decoder.detection.ml_model import extract_features, get_string_rep, MLModelManager

    console = Console()
    console.print("\n[bold cyan]═" * 70)
    console.print("  CTF DECODER — MACHINE LEARNING TRAINING SUITE")
    console.print("═" * 70 + "\n")
    
    console.print(f"[*] Generating synthetic CTF dataset ({samples} samples)...")
    start_time = time.time()
    raw_data = generate_dataset(samples)
    gen_time = time.time() - start_time
    console.print(f"[+] Dataset generated successfully in [yellow]{gen_time:.2f}s[/yellow].")
    
    # Distribution
    distribution = {}
    for _, label in raw_data:
        distribution[label] = distribution.get(label, 0) + 1
        
    dist_table = Table(title="Class Distribution", box=rbox.SIMPLE_HEAVY, header_style="bold magenta")
    dist_table.add_column("Codec / Target Class")
    dist_table.add_column("Count", justify="right")
    dist_table.add_column("Proportion", justify="right")
    for label, count in sorted(distribution.items(), key=lambda x: -x[1]):
        dist_table.add_row(label, str(count), f"{count/len(raw_data):.1%}")
    console.print(dist_table)
    
    console.print("\n[*] Extracting numerical statistics and string representations...")
    X_num = []
    X_str = []
    y = []
    
    start_time = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Extracting...", total=len(raw_data))
        for data_bytes, label in raw_data:
            features = extract_features(data_bytes)
            text_rep = get_string_rep(data_bytes)
            X_num.append(features)
            X_str.append(text_rep)
            y.append(label)
            progress.advance(task)
            
    feat_time = time.time() - start_time
    console.print(f"[+] Extracted features for {len(X_num)} samples in [yellow]{feat_time:.2f}s[/yellow].")
    
    console.print("\n[*] Training Heavy Custom Ensemble (RF + ET) heavily...")
    start_time = time.time()
    results = MLModelManager.train_and_save(X_num, X_str, y, estimators=estimators)
    train_time = time.time() - start_time
    console.print(f"[+] Training and serialization finished in [yellow]{train_time:.2f}s[/yellow].")
    
    # Classification report
    console.print("\n[bold cyan]═" * 70)
    console.print("  CLASSIFICATION REPORT (VALIDATION SET)")
    console.print("═" * 70 + "\n")
    
    report_table = Table(title="Evaluation Metrics", box=rbox.SIMPLE_HEAVY, header_style="bold green")
    report_table.add_column("Class")
    report_table.add_column("Precision", justify="right")
    report_table.add_column("Recall", justify="right")
    report_table.add_column("F1-Score", justify="right")
    report_table.add_column("Support", justify="right")
    
    rep = results["report"]
    for label, metrics in sorted(rep.items()):
        if label in ["accuracy", "macro avg", "weighted avg"]:
            continue
        report_table.add_row(
            label,
            f"{metrics['precision']:.3f}",
            f"{metrics['recall']:.3f}",
            f"{metrics['f1-score']:.3f}",
            str(int(metrics['support']))
        )
        
    report_table.add_section()
    report_table.add_row(
        "Accuracy",
        "",
        "",
        f"[bold green]{results['accuracy']:.3%}[/bold green]",
        str(int(rep['weighted avg']['support']))
    )
    
    console.print(report_table)
    console.print("\n[bold green][✔] ML Model trained heavily and verified successfully![/bold green]\n")


@cli.command()
@click.option('--host', default='127.0.0.1', help='Bind host')
@click.option('--port', default=8000, help='Bind port')
@click.option('--reload', is_flag=True, help='Enable auto-reload (dev mode)')
def serve(host, port, reload):
    """Start the CTF Decoder Web UI server."""
    try:
        import uvicorn
    except ImportError:
        click.echo("Error: uvicorn not installed. Run: pip install uvicorn[standard]", err=True)
        sys.exit(1)
    click.echo(f"[*] CTF Decoder Web UI starting at http://{host}:{port}")
    click.echo(f"[*] Open your browser and navigate to http://{host}:{port}")
    uvicorn.run(
        "ctf_decoder.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == '__main__':
    cli()

