"""
OutputFormatter - Renders PipelineResult to terminal (Rich) or JSON.
"""

from __future__ import annotations
import json
import sys
from typing import List, Optional

# Force UTF-8 stdout on Windows to avoid cp1252 encoding errors
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from ctf_decoder.core.pipeline import PipelineResult
from ctf_decoder.output.ranker import ResultRanker, PlaintextScore
from ctf_decoder.output.flag_detector import FlagDetector, FlagMatch

console = Console(highlight=False)
_ranker = ResultRanker()


def _safe_display(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return repr(data)


# --------------------------------------------------------------------------- #
# JSON formatter                                                               #
# --------------------------------------------------------------------------- #

def format_json(
    result: PipelineResult,
    score: Optional[PlaintextScore] = None,
    flags: Optional[List[FlagMatch]] = None,
) -> str:
    steps = [
        {"codec": s.codec, "output": _safe_display(s.output), "error": s.error}
        for s in result.steps
    ]
    out = {
        "success": result.success,
        "final_output": _safe_display(result.final_output) if result.final_output else None,
        "steps": steps,
        "error": result.error,
    }
    if score:
        out["plaintext_score"] = {
            "total": score.total,
            "printable_ascii": score.printable_ascii,
            "english_freq": score.english_freq,
            "bigram_freq": score.bigram_freq,
            "word_match": score.word_match,
            "flag_bonus": score.flag_bonus,
        }
    if flags:
        out["flags"] = [{"value": f.value, "position": f.start} for f in flags]

    return json.dumps(out, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Rich terminal formatter                                                      #
# --------------------------------------------------------------------------- #

def format_rich(
    result: PipelineResult,
    score: Optional[PlaintextScore] = None,
    flags: Optional[List[FlagMatch]] = None,
    verbose: bool = False,
):
    if not result.success:
        console.print(f"[bold red]FAIL:[/bold red] {result.error}")
        return

    # Decode chain table (only when --verbose and multiple steps)
    if verbose and len(result.steps) > 1:
        chain_table = Table(
            title="Decode Chain",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
        )
        chain_table.add_column("#", style="dim", width=4)
        chain_table.add_column("Codec", style="bold")
        chain_table.add_column("Output")

        for i, step in enumerate(result.steps, 1):
            display = _safe_display(step.output)
            if len(display) > 80:
                display = display[:77] + "..."
            chain_table.add_row(str(i), step.codec, display)

        console.print(chain_table)

    # Final output panel
    final_text = _safe_display(result.final_output)
    console.print(Panel(
        final_text,
        title="[bold green]Decoded Output[/bold green]",
        border_style="green",
        expand=False,
    ))

    # Flag annotations
    if flags:
        for flag in flags:
            t = Text()
            t.append("[FLAG] ", style="bold yellow")
            t.append(flag.value, style="bold white on dark_red")
            console.print(t)

    # Plaintext score breakdown (verbose)
    if verbose and score:
        st = Table(box=box.MINIMAL, show_header=False, padding=(0, 1))
        st.add_column("Component", style="dim")
        st.add_column("Score", justify="right")
        st.add_row("Printable ASCII", f"{score.printable_ascii:.2%}")
        st.add_row("English letter freq", f"{score.english_freq:.2%}")
        st.add_row("Bigram freq", f"{score.bigram_freq:.2%}")
        st.add_row("Word match", f"{score.word_match:.2%}")
        if score.flag_bonus:
            st.add_row("[yellow]Flag bonus[/yellow]", f"+{score.flag_bonus:.2f}")
        st.add_row("[bold]Total[/bold]", f"[bold]{score.total:.2%}[/bold]")
        console.print(Panel(st, title="Plaintext Score", border_style="cyan", expand=False))


# --------------------------------------------------------------------------- #
# Top-level entry point                                                        #
# --------------------------------------------------------------------------- #

def evaluate_and_display(
    result: PipelineResult,
    as_json: bool = False,
    verbose: bool = False,
    flag_patterns: Optional[List[str]] = None,
):
    """Score output, detect flags, apply implicit adaptive feedback, then render."""
    score: Optional[PlaintextScore] = None
    flags: Optional[List[FlagMatch]] = None

    if result.success and result.final_output is not None:
        detector = FlagDetector(extra_patterns=flag_patterns)
        flags = detector.detect(result.final_output)
        score = _ranker.score(result.final_output, has_flag=flags)

        # ── Full Adaptive Engine Memory Integration ────────────────────────
        if flags:
            from ctf_decoder.adaptive.memory import (
                memory_db, session, build_solve_event, DecodeAttempt
            )
            from ctf_decoder.detection.entropy import calculate_entropy
            import hashlib

            codec_chain = [s.codec for s in result.steps]
            raw_input = result.steps[0].output if result.steps else b""
            entropy = calculate_entropy(result.final_output)

            # 1. Flag-verified implicit prior update (+0.8 weight per ADAPTIVE_ENGINE.md)
            for step in result.steps:
                prior = memory_db.get_prior(step.codec)
                memory_db.set_prior(step.codec, prior.alpha + 0.8, prior.beta)

            # 2. Infer platform from flag format
            import re
            platform = None
            FLAG_PLATFORM_MAP = {
                r"picoCTF\{": "picoCTF",
                r"HTB\{": "HackTheBox",
                r"THM\{": "TryHackMe",
                r"DUCTF\{": "DownUnderCTF",
                r"FLAG\{": "generic",
            }
            flag_val = flags[0].value if flags else ""
            for pattern, pl in FLAG_PLATFORM_MAP.items():
                if re.search(pattern, flag_val):
                    platform = pl
                    session.platform_hint = platform
                    break

            # 3. Record full SolveEvent to DB + events.jsonl
            ev = build_solve_event(
                session_id=session.session_id,
                input_bytes=result.final_output,
                input_entropy=entropy,
                codec_chain=codec_chain,
                platform=platform,
                flag_format=flag_val or None,
            )
            memory_db.record_solve(ev)

            # 4. Upsert chain template
            memory_db.upsert_chain_template(codec_chain, platform=platform, success=True)

            # 5. Update platform profile
            if platform:
                memory_db.update_platform_profile(platform, codec_chain)

            # 6. Record attempt in session short-term memory
            attempt = DecodeAttempt(
                codec_chain=codec_chain,
                input_bytes_hash=ev.input_hash,
                success=True,
                had_flag=True,
            )
            session.record_attempt(attempt)

    if as_json:
        print(format_json(result, score, flags))
    else:
        format_rich(result, score, flags, verbose=verbose)
