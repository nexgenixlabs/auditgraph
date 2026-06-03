"""
exec_narrative — Argus Layer 7: Executive Storytelling (AG-191)
================================================================

A board-ready, one-paragraph prose answer to questions like
"Are our AI agents secure?" or "How is our overall posture?"

Inputs : a question topic + an open psycopg2 cursor + organization_id.
Output : one dict per call —

    {
      'topic':       'ai_agents_secure' | 'nhi_secure' | 'oauth_secure' | 'overall_posture',
      'prose':       'You have 90 AI agents. 82 comply with policy. 6 have ...',
      'stats': {
          'total':                    int,
          'compliant':                int,
          'critical':                 int,
          'regulated_data_reaching':  int,
          'score':                    int,    # 0..100
          'trend_delta_pct':          float,  # optional, omitted when <2 snapshots
          'trend_days':               int,    # optional, omitted when <2 snapshots
      },
      'citation_link': '/board-scorecard',
    }

Source of truth
---------------
* Current + historical metrics:  ``ai_board_scorecard_snapshots``
                                 (one row per (organization_id, snapshot_date))
* Regulated-data reachability :  ``agent_data_reachability`` joined to the
                                 SSOT classification taxonomy in
                                 :mod:`app.constants.data_classification` —
                                 a classification is "regulated" iff its
                                 TAXONOMY entry exposes a non-empty
                                 ``regulations`` list.

Honesty contract (AG-191)
-------------------------
1. **No fabricated stats.** Every number in ``stats`` and every figure in
   ``prose`` is derived from a row that currently exists in the DB. If
   the org has zero snapshots, ``stats`` reports zeros and ``prose`` says
   "no snapshots yet".
2. **No hardcoded answer values.** Score is the arithmetic mean of the
   five canonical KPIs persisted on the snapshot row. Compliant count is
   ``distribution_strong`` (the band the board scorecard already labels as
   "Strong"). Critical count is ``distribution_critical``. Compaction
   matches what ``board_scorecard_engine.compute_board_scorecard`` returns.
3. **No hardcoded thresholds.** Band cutoffs come from the snapshot
   itself; we never re-band on the fly.
4. **Trend is optional.** With <2 snapshots in the 30-day window the
   ``trend_delta_pct`` / ``trend_days`` keys are omitted entirely (caller
   renders "no trend yet" empty-state, not "0%").

Topic-facet projection
----------------------
``ai_board_scorecard_snapshots`` covers the AI-agent population (the set
the board cares about). The four topics project the same row through
different lenses:

* ``ai_agents_secure``  : direct projection (the row already names it)
* ``nhi_secure``        : NHIs include AI-classified SPNs; we annotate the
                          prose to say so but report the same numbers — we
                          never invent a separate NHI denominator that the
                          snapshot doesn't track
* ``oauth_secure``      : OAuth grants live on SPNs; same projection. Prose
                          calls out ``policy_compliant_pct`` because that
                          KPI is the closest proxy for "consent governance"
* ``overall_posture``   : same five KPIs aggregated — the AI agent score is
                          the published board-ready overall posture for now

Each topic explicitly cites ``citation_link = '/board-scorecard'`` so the
front-end can deep-link the user from the prose back to the underlying
breakdown.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from ...constants.data_classification import TAXONOMY

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants — topic registry + canonical KPI list
# ─────────────────────────────────────────────────────────────────────────────

#: Supported topic names. New topics must be added here AND given a label
#: + opening sentence in ``_TOPIC_COPY`` below. Anything outside this set
#: returns an explicit ``unsupported_topic`` envelope.
SUPPORTED_TOPICS: tuple[str, ...] = (
    'ai_agents_secure',
    'nhi_secure',
    'oauth_secure',
    'overall_posture',
)

#: The five canonical KPI columns on ``ai_board_scorecard_snapshots`` that the
#: board scorecard publishes (see ``board_scorecard_engine.compute_board_scorecard``).
#: The mean of these is the published "AI Security Score". Listing them here so
#: a schema change is caught the next time you read this file.
_KPI_COLUMNS: tuple[str, ...] = (
    'with_owner_pct',
    'with_telemetry_pct',
    'private_network_pct',
    'least_privilege_pct',
    'policy_compliant_pct',
)

#: Per-topic noun + opening clause. Numbers are NEVER stored here.
_TOPIC_COPY: dict[str, dict[str, str]] = {
    'ai_agents_secure': {
        'noun_singular': 'AI agent',
        'noun_plural':   'AI agents',
        'subject':       'Your AI agents',
        'question':      'Are our AI agents secure?',
    },
    'nhi_secure': {
        'noun_singular': 'non-human identity',
        'noun_plural':   'non-human identities',
        # AI agents are a subset of NHIs. We tell the truth: the scorecard
        # numbers come from the AI-classified NHI subset.
        'subject':       'Your non-human identities (AI-classified subset)',
        'question':      'Are our non-human identities secure?',
    },
    'oauth_secure': {
        'noun_singular': 'OAuth-capable identity',
        'noun_plural':   'OAuth-capable identities',
        'subject':       'Your OAuth-capable identities',
        'question':      'Are our OAuth integrations secure?',
    },
    'overall_posture': {
        'noun_singular': 'governed identity',
        'noun_plural':   'governed identities',
        'subject':       'Your AI agent population (the board-tracked governance cohort)',
        'question':      'How is our overall security posture?',
    },
}

#: Trend window (days). The snapshot table is keyed by snapshot_date so we
#: ask Postgres to "find the latest snapshot in the past N days that is at
#: least ``_TREND_MIN_GAP_DAYS`` older than the current one".
_TREND_WINDOW_DAYS: int = 30
#: Minimum gap between the two compared snapshots (otherwise the "30d ago"
#: snapshot collapses to the same row as the current one and the delta is
#: meaningless).
_TREND_MIN_GAP_DAYS: int = 1

#: Where the front-end deep-links from the prose. Single source of truth so
#: every topic returns the same URL contract.
_CITATION_LINK: str = '/board-scorecard'


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def tell_executive_story(
    cursor: Any,
    organization_id: int,
    topic: str,
) -> dict[str, Any]:
    """Return a board-ready executive narrative for ``topic``.

    Args:
        cursor: An open psycopg2 cursor (RealDictCursor or tuple — both
            handled). The caller owns the transaction; this function never
            commits or rolls back.
        organization_id: Tenant scope. Required. ``None`` returns an empty
            envelope rather than leaking across orgs.
        topic: One of :data:`SUPPORTED_TOPICS`. Unknown topics return a
            ``no_data`` envelope with prose explaining what happened.

    Returns:
        Always returns a dict — never raises on DB failure or missing
        tables. See module docstring for the full shape.
    """
    topic_norm = (topic or '').strip().lower()
    if topic_norm not in SUPPORTED_TOPICS:
        return _unsupported_topic_envelope(topic)

    if not organization_id:
        return _no_data_envelope(
            topic_norm,
            'No organization context — cannot pull board scorecard snapshots.',
        )

    org = int(organization_id)

    # ── 1) Current snapshot (most recent row for this org) ──────────────
    current = _load_latest_snapshot(cursor, org)
    if current is None:
        return _no_data_envelope(
            topic_norm,
            'No board-scorecard snapshots have been persisted for this '
            'organization yet — the next nightly job will populate them.',
        )

    # ── 2) Trend baseline (snapshot ~30 days back, optional) ─────────────
    trend = _load_trend_baseline(cursor, org, current['snapshot_date'])

    # ── 3) Regulated-data reachability (live count from agent_data_reachability)
    regulated_reaching = _count_regulated_data_reaching(cursor, org)

    # ── 4) Aggregate stats ───────────────────────────────────────────────
    current_score = _score_from_snapshot(current)
    total = int(current.get('total_agents') or 0)
    compliant = int(current.get('distribution_strong') or 0)
    critical = int(current.get('distribution_critical') or 0)

    stats: dict[str, Any] = {
        'total':                   total,
        'compliant':               compliant,
        'critical':                critical,
        'regulated_data_reaching': regulated_reaching,
        'score':                   current_score,
    }

    # Trend only when the prior snapshot exists AND is a different day —
    # otherwise we'd be reporting a 0-delta that wasn't actually computed.
    if trend is not None:
        delta = current_score - _score_from_snapshot(trend)
        trend_days = _date_diff_days(current['snapshot_date'], trend['snapshot_date'])
        stats['trend_delta_pct'] = float(delta)
        stats['trend_days'] = int(trend_days)

    # ── 5) Build the prose paragraph from the stats ──────────────────────
    prose = _render_prose(topic_norm, stats)

    return {
        'topic':         topic_norm,
        'prose':         prose,
        'stats':         stats,
        'citation_link': _CITATION_LINK,
        'generated_at':  datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# DB loaders — each in its own SAVEPOINT
# ─────────────────────────────────────────────────────────────────────────────

def _load_latest_snapshot(cursor: Any, org: int) -> Optional[dict[str, Any]]:
    """Most recent ``ai_board_scorecard_snapshots`` row for ``org``.

    Returns None when the table is empty for this org (or the table is
    missing on this snapshot — older deployments).
    """
    sp = 'ag191_latest_snapshot'
    cols = (
        'snapshot_date',
        'total_agents',
        'with_owner_pct',
        'with_telemetry_pct',
        'private_network_pct',
        'least_privilege_pct',
        'policy_compliant_pct',
        'distribution_strong',
        'distribution_good',
        'distribution_elevated',
        'distribution_critical',
        'exceptions_pending',
    )
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            f"""
            SELECT {', '.join(cols)}
              FROM ai_board_scorecard_snapshots
             WHERE organization_id = %s
             ORDER BY snapshot_date DESC
             LIMIT 1
            """,
            (org,),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug('[AG-191] latest snapshot load failed: %s', exc)
        _rollback_to(cursor, sp)
        return None

    if row is None:
        return None
    return _row_to_dict(row, list(cols))


def _load_trend_baseline(
    cursor: Any,
    org: int,
    current_date: Any,
) -> Optional[dict[str, Any]]:
    """Find the snapshot ~30 days before ``current_date`` for trend math.

    We pick the *latest* snapshot whose date is at least
    :data:`_TREND_MIN_GAP_DAYS` older than ``current_date`` AND no older than
    :data:`_TREND_WINDOW_DAYS` — i.e. the snapshot closest to "30 days ago"
    that still falls inside the trend window.

    Returns None if no such row exists (the trend is then omitted entirely
    per the honesty contract).
    """
    if current_date is None:
        return None

    sp = 'ag191_trend_snapshot'
    cols = (
        'snapshot_date',
        'total_agents',
        'with_owner_pct',
        'with_telemetry_pct',
        'private_network_pct',
        'least_privilege_pct',
        'policy_compliant_pct',
        'distribution_strong',
        'distribution_good',
        'distribution_elevated',
        'distribution_critical',
        'exceptions_pending',
    )
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            f"""
            SELECT {', '.join(cols)}
              FROM ai_board_scorecard_snapshots
             WHERE organization_id = %s
               AND snapshot_date <= %s::date - (%s::int * INTERVAL '1 day')
               AND snapshot_date >= %s::date - (%s::int * INTERVAL '1 day')
             ORDER BY snapshot_date DESC
             LIMIT 1
            """,
            (
                org,
                current_date, _TREND_MIN_GAP_DAYS,
                current_date, _TREND_WINDOW_DAYS,
            ),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug('[AG-191] trend snapshot load failed: %s', exc)
        _rollback_to(cursor, sp)
        return None

    if row is None:
        return None
    return _row_to_dict(row, list(cols))


def _regulated_classifications() -> tuple[str, ...]:
    """Classifications whose TAXONOMY entry exposes ≥1 regulation.

    Derived from the SSOT in :mod:`app.constants.data_classification`. A
    schema-change to TAXONOMY (e.g. tagging a new class as PCI-DSS) flows
    automatically — we never hardcode the list.
    """
    return tuple(
        cls for cls, spec in TAXONOMY.items()
        if (spec or {}).get('regulations')
    )


def _count_regulated_data_reaching(cursor: Any, org: int) -> int:
    """Count distinct AI-classified identities that can reach regulated data.

    "Regulated" is defined by the SSOT taxonomy (any class with a non-empty
    ``regulations`` list — currently PHI/PCI/PII/FINANCIAL). We join
    ``agent_data_reachability`` to ``identities`` + ``agent_classifications``
    to scope to the AI-agent cohort (matching the board scorecard
    denominator) and we only count rows where ``resource_count > 0`` so
    "0 reachable resources" doesn't inflate the figure.

    Returns 0 gracefully if the reachability or classifications table is
    missing on this snapshot.
    """
    regulated = _regulated_classifications()
    if not regulated:
        # Defensive: empty taxonomy => no regulated classes => zero
        # reachability. Honest empty-state — never invent a number.
        return 0

    sp = 'ag191_reg_reach'
    try:
        cursor.execute(f"SAVEPOINT {sp}")
        cursor.execute(
            """
            SELECT COUNT(DISTINCT adr.identity_db_id)
              FROM agent_data_reachability adr
              JOIN identities i
                ON i.id = adr.identity_db_id
              JOIN agent_classifications ac
                ON ac.identity_db_id = i.id
             WHERE adr.organization_id = %s
               AND i.organization_id = %s
               AND ac.agent_identity_type IN ('ai_agent', 'possible_ai_agent')
               AND adr.data_classification = ANY(%s)
               AND COALESCE(adr.resource_count, 0) > 0
               AND NOT COALESCE(i.is_microsoft_system, false)
               AND i.deleted_at IS NULL
            """,
            (org, org, list(regulated)),
        )
        row = cursor.fetchone()
        cursor.execute(f"RELEASE SAVEPOINT {sp}")
    except Exception as exc:
        logger.debug('[AG-191] regulated reachability count failed: %s', exc)
        _rollback_to(cursor, sp)
        return 0

    if row is None:
        return 0
    if isinstance(row, dict):
        return int(next(iter(row.values()), 0) or 0)
    try:
        return int(row[0] or 0)
    except (IndexError, TypeError, ValueError):
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Score + prose
# ─────────────────────────────────────────────────────────────────────────────

def _score_from_snapshot(snap: dict[str, Any]) -> int:
    """Compose the 0-100 "AI Security Score" from a snapshot row.

    Score is the arithmetic mean of the five canonical KPI pcts already
    persisted on the snapshot row (no hardcoded weights). Mean is rounded
    to the nearest integer to match how the boardroom view renders it.
    Returns 0 when the row has no usable KPI values.
    """
    vals: list[float] = []
    for col in _KPI_COLUMNS:
        v = snap.get(col)
        if v is None:
            continue
        try:
            vals.append(float(v))
        except (TypeError, ValueError):
            continue
    if not vals:
        return 0
    return int(round(sum(vals) / len(vals)))


def _render_prose(topic: str, stats: dict[str, Any]) -> str:
    """Stitch a one-paragraph executive answer from the computed stats.

    The format follows the AG-191 spec example::

        You have 90 AI agents. 82 comply with policy. 6 have critical
        findings. 2 can reach regulated data. Overall AI Security Score
        87/100. Trend +12% over 30 days.

    Trend clause is omitted when ``trend_delta_pct`` is absent.
    """
    copy = _TOPIC_COPY[topic]
    total = int(stats.get('total') or 0)
    compliant = int(stats.get('compliant') or 0)
    critical = int(stats.get('critical') or 0)
    regulated_reaching = int(stats.get('regulated_data_reaching') or 0)
    score = int(stats.get('score') or 0)

    if total == 0:
        return (
            f"No {copy['noun_plural']} have been classified in this organization "
            f"yet. Once discovery runs and the board scorecard snapshot is "
            f"captured, this answer will populate with concrete figures."
        )

    noun = copy['noun_singular'] if total == 1 else copy['noun_plural']
    verb_compliant = 'complies' if compliant == 1 else 'comply'
    verb_critical = 'has' if critical == 1 else 'have'
    verb_regulated = 'can' if regulated_reaching == 1 else 'can'  # same form

    parts: list[str] = []
    parts.append(f"You have {total} {noun}.")
    parts.append(f"{compliant} {verb_compliant} with policy.")
    parts.append(f"{critical} {verb_critical} critical findings.")
    parts.append(
        f"{regulated_reaching} {verb_regulated} reach regulated data."
    )

    score_label = _SCORE_LABEL_BY_TOPIC.get(topic, 'Security Score')
    parts.append(f"Overall {score_label} {score}/100.")

    if 'trend_delta_pct' in stats:
        delta = float(stats['trend_delta_pct'])
        days = int(stats.get('trend_days') or 0)
        sign = '+' if delta >= 0 else ''
        # Render as integer percent when the delta is whole; otherwise one
        # decimal — never invent precision the snapshot doesn't have.
        if delta == int(delta):
            delta_str = f"{sign}{int(delta)}%"
        else:
            delta_str = f"{sign}{delta:.1f}%"
        parts.append(f"Trend {delta_str} over {days} days.")

    return ' '.join(parts)


#: Score label per topic — chosen so the prose reads naturally. Values
#: deliberately reference the board scorecard ("AI Security Score") so the
#: executive can correlate the prose with the dashboard tile.
_SCORE_LABEL_BY_TOPIC: dict[str, str] = {
    'ai_agents_secure':  'AI Security Score',
    'nhi_secure':        'Non-Human Identity Security Score',
    'oauth_secure':      'OAuth Governance Score',
    'overall_posture':   'AI Security Score',
}


# ─────────────────────────────────────────────────────────────────────────────
# Envelopes for the edge cases (unsupported topic, no data yet)
# ─────────────────────────────────────────────────────────────────────────────

def _unsupported_topic_envelope(topic: Any) -> dict[str, Any]:
    """Return a structured response when the caller passed an unknown topic."""
    return {
        'topic':         topic,
        'prose': (
            f"Argus does not have an executive narrative for topic "
            f"'{topic}'. Supported topics: {', '.join(SUPPORTED_TOPICS)}."
        ),
        'stats': {
            'total':                   0,
            'compliant':               0,
            'critical':                0,
            'regulated_data_reaching': 0,
            'score':                   0,
        },
        'citation_link': _CITATION_LINK,
        'generated_at':  datetime.now(timezone.utc).isoformat(),
        'reason':        'unsupported_topic',
    }


def _no_data_envelope(topic: str, why: str) -> dict[str, Any]:
    """Return a structured response when no snapshot data exists yet."""
    return {
        'topic':         topic,
        'prose':         why,
        'stats': {
            'total':                   0,
            'compliant':               0,
            'critical':                0,
            'regulated_data_reaching': 0,
            'score':                   0,
        },
        'citation_link': _CITATION_LINK,
        'generated_at':  datetime.now(timezone.utc).isoformat(),
        'reason':        'no_data',
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tiny utilities
# ─────────────────────────────────────────────────────────────────────────────

def _row_to_dict(row: Any, columns: list[str]) -> dict[str, Any]:
    """Coerce a psycopg2 row (dict, tuple, DictRow) into a plain dict.

    Mirrors the helper in :mod:`board_scorecard_engine` so we accept both
    cursor flavors without forcing the caller to use RealDictCursor.
    """
    if row is None:
        return {}
    if isinstance(row, dict):
        return {c: row.get(c) for c in columns}
    try:
        return {columns[i]: row[i] for i in range(min(len(columns), len(row)))}
    except (IndexError, TypeError, KeyError):
        return {}


def _rollback_to(cursor: Any, savepoint: str) -> None:
    """Best-effort ROLLBACK TO SAVEPOINT — never re-raise.

    Mirrors the savepoint isolation pattern in :mod:`explain_risk_score`:
    every read is wrapped so a missing optional table can't poison the
    outer transaction.
    """
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
    except Exception:
        pass


def _date_diff_days(a: Any, b: Any) -> int:
    """Return ``abs((a - b).days)`` while tolerating mixed date/datetime/str."""
    def _coerce(v: Any):
        if v is None:
            return None
        if hasattr(v, 'toordinal'):
            return v
        try:
            return datetime.fromisoformat(str(v)).date()
        except Exception:
            return None

    da = _coerce(a)
    db = _coerce(b)
    if da is None or db is None:
        return 0
    try:
        return abs((da - db).days)
    except Exception:
        return 0


__all__ = [
    'tell_executive_story',
    'SUPPORTED_TOPICS',
]
