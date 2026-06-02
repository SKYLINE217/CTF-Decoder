"""
memory.py — Full persistent memory store for the Adaptive Engine.

Implements the complete schema from ADAPTIVE_ENGINE.md:
  - codec_priors    : Beta distribution per codec (Bayesian)
  - solve_events    : Immutable solve log
  - chain_templates : Frequently successful decoder chains
  - platform_profiles : Per-platform encoding style models

Also maintains an append-only events.jsonl event log alongside the DB.
"""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CodecPrior:
    alpha: float
    beta: float
    last_updated: str

    @property
    def expected_value(self) -> float:
        """E[Beta(alpha, beta)] = alpha / (alpha + beta)"""
        return self.alpha / (self.alpha + self.beta)

    @property
    def sample_count(self) -> float:
        """Effective number of observations (above the uniform prior)."""
        return self.alpha + self.beta - 2.0


@dataclass
class SolveEvent:
    id: str
    session_id: str
    solved_at: str
    input_hash: str
    input_length: int
    input_entropy: float
    codec_chain: List[str]
    chain_depth: int
    detection_rank: Optional[int]
    time_to_solve: Optional[float]
    platform: Optional[str]
    flag_format: Optional[str]


@dataclass
class ChainTemplate:
    chain_json: str          # JSON-serialised list of codec names
    frequency: int
    success_rate: float
    last_seen: str
    platform: Optional[str]

    @property
    def chain(self) -> List[str]:
        return json.loads(self.chain_json)


@dataclass
class PlatformProfile:
    platform: str
    codec_weights: Dict[str, float]
    common_chains: List[List[str]]
    total_solves: int
    last_updated: str


# ─────────────────────────────────────────────────────────────────────────────
# MemoryDB
# ─────────────────────────────────────────────────────────────────────────────

class MemoryDB:
    """Thread-safe SQLite memory store for the adaptive engine."""

    DECAY_HALF_LIFE_DAYS = 90

    def __init__(self, db_path: Optional[str] = None, event_log_path: Optional[str] = None):
        import os
        import tempfile
        
        is_serverless = os.environ.get("VERCEL") == "1" or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") is not None
        
        if db_path is None:
            if is_serverless:
                db_path = ":memory:"
            else:
                try:
                    home = Path.home() / ".ctf_decoder"
                    home.mkdir(exist_ok=True)
                    db_path = str(home / "memory.db")
                except Exception:
                    db_path = ":memory:"

        if event_log_path is None:
            if db_path == ":memory:":
                event_log_path = str(Path(tempfile.gettempdir()) / "events.jsonl")
            else:
                home = Path(db_path).parent
                event_log_path = str(home / "events.jsonl")

        self.db_path = db_path
        self.event_log_path = Path(event_log_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        c = self.conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS codec_priors (
                codec        TEXT PRIMARY KEY,
                alpha        REAL NOT NULL DEFAULT 1.0,
                beta         REAL NOT NULL DEFAULT 1.0,
                last_updated TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS solve_events (
                id             TEXT PRIMARY KEY,
                session_id     TEXT NOT NULL,
                solved_at      TEXT NOT NULL,
                input_hash     TEXT NOT NULL,
                input_length   INTEGER NOT NULL,
                input_entropy  REAL NOT NULL,
                codec_chain    TEXT NOT NULL,
                chain_depth    INTEGER NOT NULL,
                detection_rank INTEGER,
                time_to_solve  REAL,
                platform       TEXT,
                flag_format    TEXT
            );

            CREATE TABLE IF NOT EXISTS chain_templates (
                chain_json   TEXT NOT NULL,
                frequency    INTEGER NOT NULL DEFAULT 1,
                success_rate REAL NOT NULL DEFAULT 1.0,
                last_seen    TEXT NOT NULL,
                platform     TEXT,
                PRIMARY KEY (chain_json, platform)
            );

            CREATE TABLE IF NOT EXISTS platform_profiles (
                platform      TEXT PRIMARY KEY,
                codec_weights TEXT NOT NULL,
                common_chains TEXT NOT NULL,
                total_solves  INTEGER NOT NULL DEFAULT 0,
                last_updated  TEXT NOT NULL
            );
        """)
        self.conn.commit()

    # ── Codec priors ──────────────────────────────────────────────────────────

    def get_prior(self, codec: str) -> CodecPrior:
        c = self.conn.cursor()
        c.execute('SELECT alpha, beta, last_updated FROM codec_priors WHERE codec = ?', (codec,))
        row = c.fetchone()
        if row:
            return CodecPrior(row['alpha'], row['beta'], row['last_updated'])
        return CodecPrior(1.0, 1.0, _now())

    def set_prior(self, codec: str, alpha: float, beta: float, touch: bool = True) -> None:
        ts = _now() if touch else self.get_prior(codec).last_updated
        c = self.conn.cursor()
        c.execute("""
            INSERT INTO codec_priors (codec, alpha, beta, last_updated)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(codec) DO UPDATE SET
                alpha=excluded.alpha,
                beta=excluded.beta,
                last_updated=excluded.last_updated
        """, (codec, max(1.0, alpha), max(1.0, beta), ts))
        self.conn.commit()

    def update_prior(self, codec: str, was_correct: bool) -> None:
        """Bayesian update rule from ADAPTIVE_ENGINE.md."""
        prior = self.get_prior(codec)
        if was_correct:
            self.set_prior(codec, prior.alpha + 1.0, prior.beta)
        else:
            self.set_prior(codec, prior.alpha, prior.beta + 1.0)

    def get_all_priors(self) -> List[Tuple[str, CodecPrior]]:
        c = self.conn.cursor()
        c.execute('SELECT codec, alpha, beta, last_updated FROM codec_priors')
        return [(r['codec'], CodecPrior(r['alpha'], r['beta'], r['last_updated']))
                for r in c.fetchall()]

    def apply_decay(self) -> None:
        """
        Decay codec priors toward uniform (alpha=1, beta=1) based on
        days since last update. Half-life = DECAY_HALF_LIFE_DAYS.
        """
        now = datetime.now(timezone.utc)
        for codec, prior in self.get_all_priors():
            try:
                last = datetime.fromisoformat(prior.last_updated.replace('Z', '+00:00'))
            except ValueError:
                continue
            days = (now - last).days
            factor = 0.5 ** (days / self.DECAY_HALF_LIFE_DAYS)
            new_alpha = 1.0 + (prior.alpha - 1.0) * factor
            new_beta  = 1.0 + (prior.beta  - 1.0) * factor
            self.set_prior(codec, new_alpha, new_beta, touch=False)

    # ── Solve events ──────────────────────────────────────────────────────────

    def record_solve(self, event: SolveEvent) -> None:
        c = self.conn.cursor()
        c.execute("""
            INSERT OR IGNORE INTO solve_events
            (id, session_id, solved_at, input_hash, input_length, input_entropy,
             codec_chain, chain_depth, detection_rank, time_to_solve, platform, flag_format)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.id, event.session_id, event.solved_at,
            event.input_hash, event.input_length, event.input_entropy,
            json.dumps(event.codec_chain), event.chain_depth,
            event.detection_rank, event.time_to_solve,
            event.platform, event.flag_format,
        ))
        self.conn.commit()
        # Append to immutable JSON Lines log
        try:
            with self.event_log_path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(asdict(event)) + '\n')
        except Exception:
            pass

    def get_recent_solve_events(self, days: int = 90) -> List[SolveEvent]:
        c = self.conn.cursor()
        c.execute("""
            SELECT * FROM solve_events
            WHERE solved_at >= datetime('now', ?)
            ORDER BY solved_at DESC
        """, (f'-{days} days',))
        return [self._row_to_solve_event(r) for r in c.fetchall()]

    @staticmethod
    def _row_to_solve_event(r: sqlite3.Row) -> SolveEvent:
        return SolveEvent(
            id=r['id'], session_id=r['session_id'], solved_at=r['solved_at'],
            input_hash=r['input_hash'], input_length=r['input_length'],
            input_entropy=r['input_entropy'],
            codec_chain=json.loads(r['codec_chain']),
            chain_depth=r['chain_depth'], detection_rank=r['detection_rank'],
            time_to_solve=r['time_to_solve'], platform=r['platform'],
            flag_format=r['flag_format'],
        )

    # ── Chain templates ───────────────────────────────────────────────────────

    def upsert_chain_template(
        self,
        chain: List[str],
        platform: Optional[str] = None,
        success: bool = True,
    ) -> None:
        chain_json = json.dumps(chain)
        c = self.conn.cursor()
        c.execute("""
            SELECT frequency, success_rate FROM chain_templates
            WHERE chain_json = ? AND (platform IS ? OR platform = ?)
        """, (chain_json, platform, platform))
        row = c.fetchone()

        if row:
            freq = row['frequency'] + 1
            new_sr = (row['success_rate'] * row['frequency'] + (1.0 if success else 0.0)) / freq
            c.execute("""
                UPDATE chain_templates
                SET frequency=?, success_rate=?, last_seen=?
                WHERE chain_json=? AND (platform IS ? OR platform=?)
            """, (freq, new_sr, _now(), chain_json, platform, platform))
        else:
            c.execute("""
                INSERT INTO chain_templates (chain_json, frequency, success_rate, last_seen, platform)
                VALUES (?, 1, ?, ?, ?)
            """, (chain_json, 1.0 if success else 0.0, _now(), platform))

        self.conn.commit()

    def get_chain_templates(
        self,
        platform: Optional[str] = None,
        min_frequency: int = 1,
        min_success_rate: float = 0.0,
    ) -> List[ChainTemplate]:
        c = self.conn.cursor()
        c.execute("""
            SELECT * FROM chain_templates
            WHERE frequency >= ?
              AND success_rate >= ?
              AND (platform IS NULL OR platform = ?)
            ORDER BY frequency * success_rate DESC
        """, (min_frequency, min_success_rate, platform))
        return [
            ChainTemplate(
                chain_json=r['chain_json'], frequency=r['frequency'],
                success_rate=r['success_rate'], last_seen=r['last_seen'],
                platform=r['platform'],
            )
            for r in c.fetchall()
        ]

    # ── Platform profiles ─────────────────────────────────────────────────────

    def update_platform_profile(self, platform: str, codec_chain: List[str]) -> None:
        c = self.conn.cursor()
        c.execute('SELECT * FROM platform_profiles WHERE platform = ?', (platform,))
        row = c.fetchone()

        if row:
            weights: Dict[str, float] = json.loads(row['codec_weights'])
            chains: List[List[str]] = json.loads(row['common_chains'])
            total = row['total_solves'] + 1
            for codec in codec_chain:
                weights[codec] = weights.get(codec, 0.0) + 1.0
            # Normalise
            s = sum(weights.values())
            weights = {k: v / s for k, v in weights.items()}
            # Keep top 10 chains
            chains.append(codec_chain)
            chains = chains[-10:]
            c.execute("""
                UPDATE platform_profiles
                SET codec_weights=?, common_chains=?, total_solves=?, last_updated=?
                WHERE platform=?
            """, (json.dumps(weights), json.dumps(chains), total, _now(), platform))
        else:
            weights = {codec: 1.0 / len(codec_chain) for codec in codec_chain}
            c.execute("""
                INSERT INTO platform_profiles
                (platform, codec_weights, common_chains, total_solves, last_updated)
                VALUES (?, ?, ?, 1, ?)
            """, (platform, json.dumps(weights), json.dumps([codec_chain]), _now()))

        self.conn.commit()

    def get_platform_profile(self, platform: str) -> Optional[PlatformProfile]:
        c = self.conn.cursor()
        c.execute('SELECT * FROM platform_profiles WHERE platform = ?', (platform,))
        row = c.fetchone()
        if not row:
            return None
        return PlatformProfile(
            platform=row['platform'],
            codec_weights=json.loads(row['codec_weights']),
            common_chains=json.loads(row['common_chains']),
            total_solves=row['total_solves'],
            last_updated=row['last_updated'],
        )

    # ── Utilities ─────────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Wipe all adaptive data (used by ctfdec memory clear)."""
        c = self.conn.cursor()
        c.executescript("""
            DELETE FROM codec_priors;
            DELETE FROM solve_events;
            DELETE FROM chain_templates;
            DELETE FROM platform_profiles;
        """)
        self.conn.commit()
        if self.event_log_path.exists():
            self.event_log_path.unlink()


# ─────────────────────────────────────────────────────────────────────────────
# Short-Term Memory (Session Context)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DecodeAttempt:
    codec_chain: List[str]
    input_bytes_hash: str
    success: bool
    had_flag: bool
    timestamp: str = field(default_factory=_now)


@dataclass
class SessionContext:
    """In-RAM short-term memory for the duration of a single ctfdec session."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_now)
    attempts: List[DecodeAttempt] = field(default_factory=list)
    confirmed_solves: List[SolveEvent] = field(default_factory=list)
    platform_hint: Optional[str] = None

    # Running frequency counter — drives within-session boosts
    _codec_frequency: Dict[str, int] = field(default_factory=dict, repr=False)

    def record_attempt(self, attempt: DecodeAttempt) -> None:
        self.attempts.append(attempt)
        if attempt.success:
            for codec in attempt.codec_chain:
                self._codec_frequency[codec] = self._codec_frequency.get(codec, 0) + 1

    def within_session_boost(self, codec: str) -> float:
        """Extra score weight based on how often this codec worked this session."""
        freq = self._codec_frequency.get(codec, 0)
        total = sum(self._codec_frequency.values()) or 1
        return (freq / total) * 0.15  # max +15% boost

    def summary(self) -> str:
        solves = len(self.confirmed_solves)
        top = sorted(self._codec_frequency.items(), key=lambda x: x[1], reverse=True)
        top_str = ", ".join(c for c, _ in top[:3]) or "none"
        return (
            f"Session {self.session_id[:8]} | "
            f"{len(self.attempts)} attempts | {solves} solves | "
            f"Top codecs: {top_str}"
        )




def build_solve_event(
    session_id: str,
    input_bytes: bytes,
    input_entropy: float,
    codec_chain: List[str],
    detection_rank: Optional[int] = None,
    time_to_solve: Optional[float] = None,
    platform: Optional[str] = None,
    flag_format: Optional[str] = None,
) -> SolveEvent:
    import hashlib
    return SolveEvent(
        id=str(uuid.uuid4()),
        session_id=session_id,
        solved_at=_now(),
        input_hash=hashlib.sha256(input_bytes).hexdigest(),
        input_length=len(input_bytes),
        input_entropy=input_entropy,
        codec_chain=codec_chain,
        chain_depth=len(codec_chain),
        detection_rank=detection_rank,
        time_to_solve=time_to_solve,
        platform=platform,
        flag_format=flag_format,
    )


# Module-level singletons
memory_db = MemoryDB()
session = SessionContext()
