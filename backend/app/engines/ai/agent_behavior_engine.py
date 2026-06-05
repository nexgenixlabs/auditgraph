"""
agent_behavior_engine — AG-182 Tier 3A: AI Agent Behavior Baselines + Anomalies
================================================================================

Computes a 14-day rolling behavioral baseline per AI agent from
agent_activity_events, then surfaces deviations as agent_behavior_anomalies.

This is the "CrowdStrike for AI Agents" capability:
  - Volume baselines: avg + p95 daily model invocations + records read
  - Peer/resource diversity: distinct resources touched per day
  - Temporal pattern: 24-hour activity histogram
  - Anomaly detection: volume_spike | new_peer | new_resource | off_hours_break

The Azure Monitor / ARM Activity Log ingester is a fast-follow — for now this
engine computes baselines from whatever events already exist in
agent_activity_events. If no events exist for an org, refresh_baselines returns
{evaluated: 0, written: 0, skipped: 0, reason: 'no events'} and
detect_anomalies returns []. NO fake data is invented.

Configurable thresholds live in the settings table under key
'behavior_baseline_thresholds' (JSONB):
    {volume_spike_multiplier: 3.0, off_hours_top_n: 3, lookback_hours: 24}
Defaults are fallback only — NOT the primary source.

Baselines carry an is_active flag — set when samples_count >= window_days
(14 by default). Anomaly detection MUST NOT fire while baseline.is_active = false
("still learning" period).

Honors migration 100 regression rule and Phase 87 tenant isolation: all queries
filter by organization_id explicitly (the RLS policy on the new tables already
enforces this when the connection is auditgraph_app, but we double-belt the
where-clause to make org-bypassed admin queries safe too).
"""

from __future__ import annotations

import json
import logging
import statistics
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Defaults (FALLBACK ONLY — runtime values come from settings table)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_THRESHOLDS: Dict[str, Any] = {
    "volume_spike_multiplier": 3.0,
    "off_hours_top_n":         3,
    "lookback_hours":          24,
}

# Model-invocation categories — events in these categories drive the
# avg_daily_model_invocations / p95_daily_model_invocations baselines.
MODEL_INVOCATION_CATEGORIES = {"model_call"}

# Data-access categories — events in these categories drive the
# avg_daily_records_read / p95_daily_records_read baselines via metric_value.
DATA_ACCESS_CATEGORIES = {"data_access", "secret_read"}


class AgentBehaviorEngine:
    """Rolling behavioral baselines + anomaly detection for AI agents.

    Usage:
        engine = AgentBehaviorEngine(db)
        engine.refresh_baselines(organization_id, window_days=14)
        anomalies = engine.detect_anomalies(organization_id, lookback_hours=24)
    """

    def __init__(self, db: Any):
        self.db = db

    # ── Settings resolution ──────────────────────────────────────────────

    def _resolve_thresholds(self, organization_id: int) -> Dict[str, Any]:
        """Read 'behavior_baseline_thresholds' from settings → merged dict.

        Settings precedence: org-scoped row beats system-scoped row beats
        DEFAULTS. The DEFAULTS dict is ONLY the fallback — every primary
        value comes from the DB when present.
        """
        thresholds = dict(DEFAULT_THRESHOLDS)
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("SAVEPOINT ag182_settings")
            # Try org-scoped first
            cursor.execute(
                "SELECT value FROM settings "
                "WHERE key = %s AND organization_id = %s "
                "LIMIT 1",
                ("behavior_baseline_thresholds", organization_id),
            )
            row = cursor.fetchone()
            if not row:
                # Fall back to system-scoped
                cursor.execute(
                    "SELECT value FROM settings "
                    "WHERE key = %s AND organization_id IS NULL "
                    "LIMIT 1",
                    ("behavior_baseline_thresholds",),
                )
                row = cursor.fetchone()
            cursor.execute("RELEASE SAVEPOINT ag182_settings")
        except Exception as exc:
            logger.debug("AG-182: thresholds lookup failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_settings")
            except Exception:
                pass
            cursor.close()
            return thresholds

        cursor.close()
        if not row:
            return thresholds

        raw = row[0]
        if raw is None:
            return thresholds

        parsed: Any = raw
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except Exception:
                logger.warning(
                    "AG-182: behavior_baseline_thresholds is not valid JSON — using defaults"
                )
                return thresholds

        if not isinstance(parsed, dict):
            return thresholds

        for k, v in parsed.items():
            if k in DEFAULT_THRESHOLDS:
                thresholds[k] = v
        return thresholds

    # ── Public: refresh baselines ────────────────────────────────────────

    def refresh_baselines(self, organization_id: int,
                          window_days: int = 14) -> Dict[str, Any]:
        """Compute baselines for every AI agent with at least one event.

        For each (identity_db_id, identity_id) pair seen in
        agent_activity_events within the last `window_days` days, aggregate
        per-day metrics and UPSERT into agent_behavior_baselines.

        is_active is set when samples_count >= window_days — baselines below
        that threshold remain inactive ("still learning"), and
        detect_anomalies will skip them.

        Returns:
            {evaluated, written, skipped, reason?}
        """
        if window_days <= 0:
            window_days = 14

        cursor = self.db.conn.cursor()

        # 1) Bail early if no events at all for this org.
        try:
            cursor.execute("SAVEPOINT ag182_event_check")
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM agent_activity_events
                     WHERE organization_id = %s
                     LIMIT 1
                )
                """,
                (organization_id,),
            )
            has_any = bool(cursor.fetchone()[0])
            cursor.execute("RELEASE SAVEPOINT ag182_event_check")
        except Exception as exc:
            logger.warning("AG-182: event existence check failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_event_check")
            except Exception:
                pass
            cursor.close()
            return {"evaluated": 0, "written": 0, "skipped": 0,
                    "reason": "event lookup failed"}

        if not has_any:
            cursor.close()
            return {"evaluated": 0, "written": 0, "skipped": 0,
                    "reason": "no events"}

        # 2) Pull per-agent, per-day rollups for the window. We compute
        # everything in Python so the engine works whether the cluster has
        # percentile_cont or not — keeps it simple and portable.
        evaluated = 0
        written = 0
        skipped = 0

        try:
            cursor.execute("SAVEPOINT ag182_load_events")
            cursor.execute(
                """
                SELECT identity_db_id,
                       identity_id,
                       category,
                       occurred_at,
                       resource_id,
                       resource_type,
                       COALESCE(metric_value, 0) AS metric_value
                  FROM agent_activity_events
                 WHERE organization_id = %s
                   AND occurred_at >= NOW() - (%s::text || ' days')::interval
                """,
                (organization_id, window_days),
            )
            event_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag182_load_events")
        except Exception as exc:
            logger.warning("AG-182: event load failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_load_events")
            except Exception:
                pass
            cursor.close()
            return {"evaluated": 0, "written": 0, "skipped": 0,
                    "reason": "event load failed"}

        # Group events by agent.
        by_agent: Dict[int, Dict[str, Any]] = {}
        for row in event_rows:
            (identity_db_id, identity_id, category, occurred_at,
             resource_id, resource_type, metric_value) = row
            if identity_db_id is None:
                continue
            iid = int(identity_db_id)
            agent = by_agent.setdefault(iid, {
                "identity_id": identity_id,
                "events": [],
            })
            agent["events"].append({
                "category": category,
                "occurred_at": occurred_at,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "metric_value": float(metric_value) if metric_value is not None else 0.0,
            })

        if not by_agent:
            cursor.close()
            return {"evaluated": 0, "written": 0, "skipped": 0,
                    "reason": "no events"}

        # 3) For each agent: compute daily series + hourly histogram, UPSERT.
        for identity_db_id, agent in by_agent.items():
            evaluated += 1
            try:
                baseline = self._compute_baseline_for_agent(
                    agent["events"], window_days
                )
            except Exception as exc:
                logger.warning(
                    "AG-182: baseline compute failed for identity_db_id=%s: %s",
                    identity_db_id, exc,
                )
                skipped += 1
                continue

            try:
                cursor.execute("SAVEPOINT ag182_upsert_baseline")
                cursor.execute(
                    """
                    INSERT INTO agent_behavior_baselines (
                        organization_id, identity_db_id, identity_id,
                        window_days,
                        avg_daily_model_invocations, p95_daily_model_invocations,
                        avg_daily_records_read, p95_daily_records_read,
                        avg_daily_distinct_peers,
                        hourly_pattern,
                        samples_count, is_active, computed_at
                    ) VALUES (
                        %s, %s, %s,
                        %s,
                        %s, %s,
                        %s, %s,
                        %s,
                        %s::jsonb,
                        %s, %s, NOW()
                    )
                    ON CONFLICT (organization_id, identity_db_id) DO UPDATE SET
                        identity_id                 = EXCLUDED.identity_id,
                        window_days                 = EXCLUDED.window_days,
                        avg_daily_model_invocations = EXCLUDED.avg_daily_model_invocations,
                        p95_daily_model_invocations = EXCLUDED.p95_daily_model_invocations,
                        avg_daily_records_read      = EXCLUDED.avg_daily_records_read,
                        p95_daily_records_read      = EXCLUDED.p95_daily_records_read,
                        avg_daily_distinct_peers    = EXCLUDED.avg_daily_distinct_peers,
                        hourly_pattern              = EXCLUDED.hourly_pattern,
                        samples_count               = EXCLUDED.samples_count,
                        is_active                   = EXCLUDED.is_active,
                        computed_at                 = NOW()
                    """,
                    (
                        organization_id,
                        identity_db_id,
                        agent["identity_id"],
                        window_days,
                        baseline["avg_daily_model_invocations"],
                        baseline["p95_daily_model_invocations"],
                        baseline["avg_daily_records_read"],
                        baseline["p95_daily_records_read"],
                        baseline["avg_daily_distinct_peers"],
                        json.dumps(baseline["hourly_pattern"]),
                        baseline["samples_count"],
                        baseline["samples_count"] >= window_days,
                    ),
                )
                cursor.execute("RELEASE SAVEPOINT ag182_upsert_baseline")
                written += 1
            except Exception as exc:
                logger.warning(
                    "AG-182: baseline upsert failed for identity_db_id=%s: %s",
                    identity_db_id, exc,
                )
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT ag182_upsert_baseline")
                except Exception:
                    pass
                skipped += 1

        try:
            self.db.conn.commit()
        except Exception as exc:
            logger.warning("AG-182: commit after baseline refresh failed: %s", exc)

        cursor.close()
        return {"evaluated": evaluated, "written": written, "skipped": skipped}

    def _compute_baseline_for_agent(self, events: List[Dict[str, Any]],
                                    window_days: int) -> Dict[str, Any]:
        """Roll up an agent's events into daily series + hourly histogram.

        All percentile / averaging is done in Python via statistics module to
        avoid depending on percentile_cont being available + accessible.
        """
        # Group events per UTC day.
        by_day: Dict[str, Dict[str, Any]] = {}
        hourly_counts: List[int] = [0] * 24

        for ev in events:
            occurred_at = ev["occurred_at"]
            if occurred_at is None:
                continue
            # Normalize to UTC + extract day key and hour bucket.
            if not isinstance(occurred_at, datetime):
                try:
                    occurred_at = datetime.fromisoformat(
                        str(occurred_at).replace("Z", "+00:00")
                    )
                except Exception:
                    continue
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=timezone.utc)
            else:
                occurred_at = occurred_at.astimezone(timezone.utc)

            day_key = occurred_at.date().isoformat()
            hour = occurred_at.hour
            if 0 <= hour < 24:
                hourly_counts[hour] += 1

            day = by_day.setdefault(day_key, {
                "model_calls": 0,
                "records_read": 0.0,
                "distinct_resources": set(),
            })

            category = ev.get("category") or ""
            if category in MODEL_INVOCATION_CATEGORIES:
                day["model_calls"] += 1
            if category in DATA_ACCESS_CATEGORIES:
                day["records_read"] += float(ev.get("metric_value") or 0.0)
            rid = ev.get("resource_id")
            if rid:
                day["distinct_resources"].add(rid)

        samples_count = len(by_day)

        if samples_count == 0:
            return {
                "avg_daily_model_invocations": 0.0,
                "p95_daily_model_invocations": 0.0,
                "avg_daily_records_read":      0.0,
                "p95_daily_records_read":      0.0,
                "avg_daily_distinct_peers":    0.0,
                "hourly_pattern":              {str(h): 0 for h in range(24)},
                "samples_count":               0,
            }

        model_series  = [d["model_calls"] for d in by_day.values()]
        record_series = [d["records_read"] for d in by_day.values()]
        peer_series   = [len(d["distinct_resources"]) for d in by_day.values()]

        return {
            "avg_daily_model_invocations": float(statistics.fmean(model_series)),
            "p95_daily_model_invocations": _percentile(model_series, 95),
            "avg_daily_records_read":      float(statistics.fmean(record_series)),
            "p95_daily_records_read":      _percentile(record_series, 95),
            "avg_daily_distinct_peers":    float(statistics.fmean(peer_series)),
            "hourly_pattern":              {str(h): hourly_counts[h] for h in range(24)},
            "samples_count":               samples_count,
        }

    # ── Public: detect anomalies ─────────────────────────────────────────

    def detect_anomalies(self, organization_id: int,
                         lookback_hours: int = 24) -> List[Dict[str, Any]]:
        """Compare last N hours of activity against each agent's baseline.

        Returns one dict per anomaly, also INSERTed into
        agent_behavior_anomalies for persistence. Anomaly types:
          - volume_spike    — observed > N× baseline p95 (configurable)
          - new_peer        — touched a resource_id not in prior 14d
          - new_resource    — touched a resource_type not in prior 14d
          - off_hours_break — event in an hour outside baseline top-N

        Skips agents with baseline.is_active = false (still learning).
        If no events exist for the org at all, returns [].
        """
        thresholds = self._resolve_thresholds(organization_id)
        spike_mult     = float(thresholds.get("volume_spike_multiplier", 3.0))
        off_hours_top  = int(thresholds.get("off_hours_top_n", 3))
        # If caller didn't override, honor the setting.
        if lookback_hours is None or lookback_hours <= 0:
            lookback_hours = int(thresholds.get("lookback_hours", 24))

        out: List[Dict[str, Any]] = []
        cursor = self.db.conn.cursor()

        # Bail if no events at all for this org.
        try:
            cursor.execute("SAVEPOINT ag182_anom_check")
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM agent_activity_events
                     WHERE organization_id = %s
                     LIMIT 1
                )
                """,
                (organization_id,),
            )
            has_any = bool(cursor.fetchone()[0])
            cursor.execute("RELEASE SAVEPOINT ag182_anom_check")
        except Exception as exc:
            logger.warning("AG-182: anomaly event existence check failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_anom_check")
            except Exception:
                pass
            cursor.close()
            return out

        if not has_any:
            cursor.close()
            return out

        # Load active baselines for this org.
        try:
            cursor.execute("SAVEPOINT ag182_load_baselines")
            cursor.execute(
                """
                SELECT identity_db_id, identity_id, window_days,
                       avg_daily_model_invocations, p95_daily_model_invocations,
                       avg_daily_records_read, p95_daily_records_read,
                       avg_daily_distinct_peers,
                       hourly_pattern, samples_count, is_active
                  FROM agent_behavior_baselines
                 WHERE organization_id = %s
                   AND is_active = TRUE
                """,
                (organization_id,),
            )
            baseline_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag182_load_baselines")
        except Exception as exc:
            logger.warning("AG-182: baseline load failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_load_baselines")
            except Exception:
                pass
            cursor.close()
            return out

        if not baseline_rows:
            cursor.close()
            return out

        for row in baseline_rows:
            (identity_db_id, identity_id, window_days,
             avg_mi, p95_mi, avg_rr, p95_rr, avg_peers,
             hourly_pattern, samples_count, is_active) = row

            if not is_active:
                continue  # Defensive — the WHERE clause already filters.

            agent_anoms = self._detect_for_agent(
                cursor=cursor,
                organization_id=organization_id,
                identity_db_id=int(identity_db_id),
                identity_id=identity_id,
                window_days=int(window_days) if window_days else 14,
                lookback_hours=lookback_hours,
                baseline={
                    "p95_daily_model_invocations": float(p95_mi or 0.0),
                    "p95_daily_records_read":      float(p95_rr or 0.0),
                    "avg_daily_model_invocations": float(avg_mi or 0.0),
                    "avg_daily_records_read":      float(avg_rr or 0.0),
                    "avg_daily_distinct_peers":    float(avg_peers or 0.0),
                    "hourly_pattern":              _coerce_hourly(hourly_pattern),
                    "samples_count":               int(samples_count or 0),
                },
                spike_multiplier=spike_mult,
                off_hours_top_n=off_hours_top,
            )
            out.extend(agent_anoms)

        # Persist anomalies — one INSERT per row, each in a SAVEPOINT so a
        # single bad insert can't poison the whole batch.
        for a in out:
            try:
                cursor.execute("SAVEPOINT ag182_insert_anom")
                cursor.execute(
                    """
                    INSERT INTO agent_behavior_anomalies (
                        organization_id, identity_db_id, identity_id,
                        anomaly_type, severity, detected_at,
                        baseline_value, observed_value, delta_pct,
                        description, related_event_ids, resolved
                    ) VALUES (
                        %s, %s, %s,
                        %s, %s, NOW(),
                        %s, %s, %s,
                        %s, %s, FALSE
                    )
                    RETURNING id, detected_at
                    """,
                    (
                        organization_id,
                        a["identity_db_id"],
                        a["identity_id"],
                        a["anomaly_type"],
                        a["severity"],
                        a.get("baseline_value"),
                        a.get("observed_value"),
                        a.get("delta_pct"),
                        a.get("description"),
                        a.get("related_event_ids") or [],
                    ),
                )
                inserted = cursor.fetchone()
                if inserted:
                    a["id"] = int(inserted[0])
                    detected_at = inserted[1]
                    a["detected_at"] = (
                        detected_at.isoformat()
                        if hasattr(detected_at, "isoformat") else str(detected_at)
                    )
                cursor.execute("RELEASE SAVEPOINT ag182_insert_anom")
            except Exception as exc:
                logger.warning("AG-182: anomaly insert failed: %s", exc)
                try:
                    cursor.execute("ROLLBACK TO SAVEPOINT ag182_insert_anom")
                except Exception:
                    pass

        try:
            self.db.conn.commit()
        except Exception as exc:
            logger.warning("AG-182: commit after anomaly detect failed: %s", exc)

        cursor.close()
        return out

    def _detect_for_agent(self, *, cursor: Any, organization_id: int,
                          identity_db_id: int, identity_id: str,
                          window_days: int, lookback_hours: int,
                          baseline: Dict[str, Any],
                          spike_multiplier: float,
                          off_hours_top_n: int) -> List[Dict[str, Any]]:
        """Per-agent anomaly detection.

        Three SQL queries per agent:
          1. Pull current-window events (last `lookback_hours`).
          2. Pull prior-window events (the rest of the baseline period) to
             compute the set of "seen" resource_ids + resource_types.
          (Both lists are tagged with id for related_event_ids.)
        """
        # 1) Current-window events.
        try:
            cursor.execute("SAVEPOINT ag182_curr_events")
            cursor.execute(
                """
                SELECT id, category, occurred_at, resource_id, resource_type,
                       COALESCE(metric_value, 0)
                  FROM agent_activity_events
                 WHERE organization_id = %s
                   AND identity_db_id  = %s
                   AND occurred_at >= NOW() - (%s::text || ' hours')::interval
                 ORDER BY occurred_at DESC
                """,
                (organization_id, identity_db_id, lookback_hours),
            )
            curr_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag182_curr_events")
        except Exception as exc:
            logger.warning(
                "AG-182: current event load failed for %s: %s",
                identity_db_id, exc,
            )
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_curr_events")
            except Exception:
                pass
            return []

        if not curr_rows:
            return []

        # 2) Prior-window events — the baseline lookback minus the current
        # window. Used to compute the "seen" resource_id + resource_type sets.
        prior_rows: List[Any] = []
        try:
            cursor.execute("SAVEPOINT ag182_prior_events")
            cursor.execute(
                """
                SELECT resource_id, resource_type
                  FROM agent_activity_events
                 WHERE organization_id = %s
                   AND identity_db_id  = %s
                   AND occurred_at <  NOW() - (%s::text || ' hours')::interval
                   AND occurred_at >= NOW() - (%s::text || ' days')::interval
                """,
                (organization_id, identity_db_id, lookback_hours, window_days),
            )
            prior_rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag182_prior_events")
        except Exception as exc:
            logger.warning(
                "AG-182: prior event load failed for %s: %s",
                identity_db_id, exc,
            )
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_prior_events")
            except Exception:
                pass
            prior_rows = []

        seen_resource_ids = {r[0] for r in prior_rows if r[0]}
        seen_resource_types = {r[1] for r in prior_rows if r[1]}

        # Aggregate the current-window slice.
        curr_model_calls = 0
        curr_records_read = 0.0
        curr_event_ids: List[int] = []
        new_peer_events: Dict[str, List[int]] = {}
        new_resource_events: Dict[str, List[int]] = {}
        off_hours_events: List[int] = []

        # Resolve top-N hours from baseline hourly_pattern.
        top_hours = _top_n_hours(baseline.get("hourly_pattern", {}), off_hours_top_n)

        for row in curr_rows:
            ev_id, category, occurred_at, resource_id, resource_type, metric_value = row
            ev_id = int(ev_id) if ev_id is not None else None
            if ev_id is not None:
                curr_event_ids.append(ev_id)

            if category in MODEL_INVOCATION_CATEGORIES:
                curr_model_calls += 1
            if category in DATA_ACCESS_CATEGORIES:
                try:
                    curr_records_read += float(metric_value or 0.0)
                except Exception:
                    pass

            if resource_id and resource_id not in seen_resource_ids:
                new_peer_events.setdefault(resource_id, []).append(ev_id) if ev_id else None
            if resource_type and resource_type not in seen_resource_types:
                new_resource_events.setdefault(resource_type, []).append(ev_id) if ev_id else None

            # Off-hours check (only when baseline has any pattern info).
            if top_hours and isinstance(occurred_at, datetime):
                occ = occurred_at
                if occ.tzinfo is None:
                    occ = occ.replace(tzinfo=timezone.utc)
                else:
                    occ = occ.astimezone(timezone.utc)
                if occ.hour not in top_hours and ev_id is not None:
                    off_hours_events.append(ev_id)

        anomalies: List[Dict[str, Any]] = []

        # ── volume_spike ────────────────────────────────────────────────
        p95_mi = baseline["p95_daily_model_invocations"]
        threshold_mi = p95_mi * spike_multiplier
        if p95_mi > 0 and curr_model_calls > threshold_mi:
            delta_pct = ((curr_model_calls - p95_mi) / p95_mi) * 100.0 if p95_mi else None
            anomalies.append({
                "identity_db_id": identity_db_id,
                "identity_id":    identity_id,
                "anomaly_type":   "volume_spike",
                "severity":       _spike_severity(curr_model_calls, p95_mi, spike_multiplier),
                "baseline_value": p95_mi,
                "observed_value": float(curr_model_calls),
                "delta_pct":      delta_pct,
                "description": (
                    f"{curr_model_calls} model invocations in the last {lookback_hours}h "
                    f"vs baseline p95 {p95_mi:.1f}/day "
                    f"(>{spike_multiplier:g}× threshold)."
                ),
                "related_event_ids": curr_event_ids[:50],
            })

        p95_rr = baseline["p95_daily_records_read"]
        threshold_rr = p95_rr * spike_multiplier
        if p95_rr > 0 and curr_records_read > threshold_rr:
            delta_pct = ((curr_records_read - p95_rr) / p95_rr) * 100.0 if p95_rr else None
            anomalies.append({
                "identity_db_id": identity_db_id,
                "identity_id":    identity_id,
                "anomaly_type":   "volume_spike",
                "severity":       _spike_severity(curr_records_read, p95_rr, spike_multiplier),
                "baseline_value": p95_rr,
                "observed_value": float(curr_records_read),
                "delta_pct":      delta_pct,
                "description": (
                    f"{curr_records_read:.0f} records read in the last {lookback_hours}h "
                    f"vs baseline p95 {p95_rr:.1f}/day "
                    f"(>{spike_multiplier:g}× threshold)."
                ),
                "related_event_ids": curr_event_ids[:50],
            })

        # ── new_peer ────────────────────────────────────────────────────
        for resource_id, ids in new_peer_events.items():
            anomalies.append({
                "identity_db_id": identity_db_id,
                "identity_id":    identity_id,
                "anomaly_type":   "new_peer",
                "severity":       "medium",
                "baseline_value": None,
                "observed_value": float(len(ids)),
                "delta_pct":      None,
                "description": (
                    f"Agent touched a resource not seen in the prior "
                    f"{window_days}d: {resource_id}"
                ),
                "related_event_ids": ids[:50],
            })

        # ── new_resource ────────────────────────────────────────────────
        for resource_type, ids in new_resource_events.items():
            anomalies.append({
                "identity_db_id": identity_db_id,
                "identity_id":    identity_id,
                "anomaly_type":   "new_resource",
                "severity":       "high",
                "baseline_value": None,
                "observed_value": float(len(ids)),
                "delta_pct":      None,
                "description": (
                    f"Agent touched a resource type not seen in the prior "
                    f"{window_days}d: {resource_type}"
                ),
                "related_event_ids": ids[:50],
            })

        # ── off_hours_break ─────────────────────────────────────────────
        if off_hours_events and top_hours:
            top_str = ", ".join(f"{h:02d}:00" for h in sorted(top_hours))
            anomalies.append({
                "identity_db_id": identity_db_id,
                "identity_id":    identity_id,
                "anomaly_type":   "off_hours_break",
                "severity":       "medium",
                "baseline_value": float(len(top_hours)),
                "observed_value": float(len(off_hours_events)),
                "delta_pct":      None,
                "description": (
                    f"{len(off_hours_events)} event(s) in the last {lookback_hours}h "
                    f"fell outside the agent's top-{off_hours_top_n} active hours "
                    f"({top_str})."
                ),
                "related_event_ids": off_hours_events[:50],
            })

        return anomalies

    # ── Public: read-side helpers ────────────────────────────────────────

    def get_timeline_for_identity(self, identity_db_id: int,
                                  organization_id: int,
                                  hours: int = 24) -> List[Dict[str, Any]]:
        """Return per-event activity timeline for a single agent."""
        if hours <= 0:
            hours = 24
        cursor = self.db.conn.cursor()
        out: List[Dict[str, Any]] = []
        try:
            cursor.execute("SAVEPOINT ag182_timeline")
            cursor.execute(
                """
                SELECT id, identity_id, category, occurred_at, source,
                       resource_id, resource_type, operation_name,
                       metric_value, severity, raw_payload, ingested_at
                  FROM agent_activity_events
                 WHERE organization_id = %s
                   AND identity_db_id  = %s
                   AND occurred_at >= NOW() - (%s::text || ' hours')::interval
                 ORDER BY occurred_at DESC
                 LIMIT 1000
                """,
                (organization_id, identity_db_id, hours),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag182_timeline")
        except Exception as exc:
            logger.warning("AG-182: timeline load failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_timeline")
            except Exception:
                pass
            cursor.close()
            return out

        for row in rows:
            (ev_id, ident, category, occurred_at, source, resource_id,
             resource_type, operation_name, metric_value, severity,
             raw_payload, ingested_at) = row
            out.append({
                "id":             int(ev_id) if ev_id is not None else None,
                "identity_id":    ident,
                "category":       category,
                "occurred_at":    _iso(occurred_at),
                "source":         source,
                "resource_id":    resource_id,
                "resource_type":  resource_type,
                "operation_name": operation_name,
                "metric_value":   float(metric_value) if metric_value is not None else None,
                "severity":       severity,
                "raw_payload":    raw_payload,
                "ingested_at":    _iso(ingested_at),
            })
        cursor.close()
        return out

    def get_baseline_for_identity(self, identity_db_id: int,
                                  organization_id: int) -> Optional[Dict[str, Any]]:
        """Return the current baseline row for an identity, or None."""
        cursor = self.db.conn.cursor()
        result: Optional[Dict[str, Any]] = None
        try:
            cursor.execute("SAVEPOINT ag182_get_baseline")
            cursor.execute(
                """
                SELECT id, identity_id, window_days,
                       avg_daily_model_invocations, p95_daily_model_invocations,
                       avg_daily_records_read, p95_daily_records_read,
                       avg_daily_distinct_peers,
                       hourly_pattern, samples_count, is_active, computed_at
                  FROM agent_behavior_baselines
                 WHERE organization_id = %s
                   AND identity_db_id  = %s
                 LIMIT 1
                """,
                (organization_id, identity_db_id),
            )
            row = cursor.fetchone()
            cursor.execute("RELEASE SAVEPOINT ag182_get_baseline")
        except Exception as exc:
            logger.warning("AG-182: baseline fetch failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_get_baseline")
            except Exception:
                pass
            cursor.close()
            return None

        cursor.close()
        if not row:
            return None

        (b_id, identity_id, window_days, avg_mi, p95_mi, avg_rr, p95_rr,
         avg_peers, hourly_pattern, samples_count, is_active, computed_at) = row
        result = {
            "id":                          int(b_id),
            "identity_db_id":              identity_db_id,
            "identity_id":                 identity_id,
            "window_days":                 int(window_days) if window_days else None,
            "avg_daily_model_invocations": float(avg_mi) if avg_mi is not None else None,
            "p95_daily_model_invocations": float(p95_mi) if p95_mi is not None else None,
            "avg_daily_records_read":      float(avg_rr) if avg_rr is not None else None,
            "p95_daily_records_read":      float(p95_rr) if p95_rr is not None else None,
            "avg_daily_distinct_peers":    float(avg_peers) if avg_peers is not None else None,
            "hourly_pattern":              _coerce_hourly(hourly_pattern),
            "samples_count":               int(samples_count) if samples_count is not None else 0,
            "is_active":                   bool(is_active),
            "computed_at":                 _iso(computed_at),
        }
        return result

    def get_recent_anomalies(self, organization_id: int,
                             limit: int = 20) -> List[Dict[str, Any]]:
        """Return the most recent anomalies for an org (resolved + unresolved)."""
        limit = max(1, min(int(limit or 20), 500))
        cursor = self.db.conn.cursor()
        out: List[Dict[str, Any]] = []
        try:
            cursor.execute("SAVEPOINT ag182_recent_anoms")
            cursor.execute(
                """
                SELECT id, identity_db_id, identity_id, anomaly_type, severity,
                       detected_at, baseline_value, observed_value, delta_pct,
                       description, related_event_ids, resolved, resolved_at
                  FROM agent_behavior_anomalies
                 WHERE organization_id = %s
                 ORDER BY detected_at DESC
                 LIMIT %s
                """,
                (organization_id, limit),
            )
            rows = cursor.fetchall()
            cursor.execute("RELEASE SAVEPOINT ag182_recent_anoms")
        except Exception as exc:
            logger.warning("AG-182: recent anomalies load failed: %s", exc)
            try:
                cursor.execute("ROLLBACK TO SAVEPOINT ag182_recent_anoms")
            except Exception:
                pass
            cursor.close()
            return out

        for row in rows:
            (a_id, identity_db_id, identity_id, anomaly_type, severity,
             detected_at, baseline_value, observed_value, delta_pct,
             description, related_event_ids, resolved, resolved_at) = row
            out.append({
                "id":                int(a_id),
                "identity_db_id":    int(identity_db_id) if identity_db_id is not None else None,
                "identity_id":       identity_id,
                "anomaly_type":      anomaly_type,
                "severity":          severity,
                "detected_at":       _iso(detected_at),
                "baseline_value":    float(baseline_value) if baseline_value is not None else None,
                "observed_value":    float(observed_value) if observed_value is not None else None,
                "delta_pct":         float(delta_pct) if delta_pct is not None else None,
                "description":       description,
                "related_event_ids": list(related_event_ids) if related_event_ids else [],
                "resolved":          bool(resolved),
                "resolved_at":       _iso(resolved_at),
            })
        cursor.close()
        return out


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _percentile(values: List[float], pct: float) -> float:
    """Compute the requested percentile of a list using the nearest-rank
    method. statistics.quantiles requires n >= 2 — fall back gracefully.
    """
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    sorted_vals = sorted(float(v) for v in values)
    # Nearest-rank: index = ceil(P/100 * N) - 1
    import math
    k = max(0, min(len(sorted_vals) - 1,
                   math.ceil((pct / 100.0) * len(sorted_vals)) - 1))
    return float(sorted_vals[k])


def _top_n_hours(hourly_pattern: Dict[str, int], top_n: int) -> set:
    """Return the set of UTC hours (0-23) with the top-N event counts.

    `hourly_pattern` is stored in JSONB as either {"0": int, ...} or {0: int, ...}.
    Ties: include all hours tied at the boundary so an attacker can't
    sneak by claiming a 1-event tie. (If 5+ hours all share the lowest top-N
    count, all are considered "normal hours".)
    """
    if not hourly_pattern or top_n <= 0:
        return set()
    # Normalize keys to ints.
    counts: List[tuple] = []
    for k, v in hourly_pattern.items():
        try:
            hour = int(k)
            count = int(v or 0)
        except (TypeError, ValueError):
            continue
        if 0 <= hour < 24:
            counts.append((hour, count))
    if not counts:
        return set()
    counts.sort(key=lambda kv: (-kv[1], kv[0]))
    if all(c == 0 for _, c in counts):
        # No baseline activity recorded — return all hours so off-hours never
        # fires. (Defensive: empty hourly_pattern in a "still-learning" race
        # could otherwise mass-fire.)
        return set(range(24))
    # Pick top_n by count, but include ties at the boundary.
    if top_n >= len(counts):
        return {h for h, c in counts if c > 0}
    boundary_count = counts[top_n - 1][1]
    return {h for h, c in counts if c >= boundary_count and c > 0}


def _spike_severity(observed: float, baseline: float, multiplier: float) -> str:
    """Spike severity tiers:
        critical = observed >= 10× baseline
        high     = observed >= 5× baseline
        medium   = observed >= multiplier× baseline  (default: 3×)
    """
    if baseline <= 0:
        return "medium"
    ratio = observed / baseline
    if ratio >= 10:
        return "critical"
    if ratio >= 5:
        return "high"
    return "medium"


def _coerce_hourly(raw: Any) -> Dict[str, int]:
    """Normalize hourly_pattern read from JSONB into {str(hour): int}.

    psycopg2 returns JSONB as either str or already-parsed dict depending on
    register_default_jsonb status. Tolerate both.
    """
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            return {}
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, int] = {}
    for k, v in raw.items():
        try:
            hour = int(k)
            count = int(v or 0)
        except (TypeError, ValueError):
            continue
        if 0 <= hour < 24:
            out[str(hour)] = count
    return out


def _iso(dt: Any) -> Optional[str]:
    """Best-effort ISO-8601 string for a datetime-like value."""
    if dt is None:
        return None
    if hasattr(dt, "isoformat"):
        try:
            return dt.isoformat()
        except Exception:
            pass
    return str(dt)


__all__ = [
    "AgentBehaviorEngine",
    "DEFAULT_THRESHOLDS",
    "MODEL_INVOCATION_CATEGORIES",
    "DATA_ACCESS_CATEGORIES",
]
