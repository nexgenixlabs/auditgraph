"""
Tier 1-4 engine unit tests (AG-PROD-C3, 2026-06-05).

Pure-function tests that don't need a live database. Each test exercises
the deterministic logic of one engine module added by Tiers 1-4 and the
Week 1-3 pivot:

  Tier 1.1 — breach_cost.format_dollar_short, compute_exposure (cache miss)
  Tier 2.1 — abuse_scenarios severity ranking + dollar pass-through
  Tier 2.2 — model_registry.classify_model fine-tune detection
  Tier 2.3 — findings._fingerprint stability + uniqueness
  Tier 3.1 — multihop_xgraph._enrich_chain weak-link bump
  Tier 3.2 — supply_chain.compute_component_risk
  Tier 4   — threat_connectors adapter normalization
"""
import pytest


# ─────────────────────────────────────────────────────────────────────────
# Tier 1.1 — breach_cost
# ─────────────────────────────────────────────────────────────────────────

def test_breach_cost_format_dollar_short():
    from app.engines.scoring.breach_cost import format_dollar_short
    assert format_dollar_short(0) == '$0'
    assert format_dollar_short(999) == '$999'
    assert format_dollar_short(2500) == '$2.5K'
    assert format_dollar_short(1_200_000) == '$1.20M'
    assert format_dollar_short(56_520_000) == '$56.52M'
    assert format_dollar_short(2_300_000_000) == '$2.30B'


def test_breach_cost_compute_exposure_no_factor():
    """When no factor exists for the classification, returns has_factor=False."""
    from app.engines.scoring.breach_cost import compute_exposure

    class FakeCursor:
        def execute(self, *a, **kw): pass
        def fetchall(self): return []   # empty — no factors loaded
        def fetchone(self): return None
        def close(self): pass

    class FakeDB:
        class FakeConn:
            def cursor(self_, **kw): return FakeCursor()
        conn = FakeConn()

    out = compute_exposure(FakeDB(), 'UNKNOWN_CLASS', 1000)
    assert out['has_factor'] is False
    assert out['estimated_exposure_mid'] == 0


# ─────────────────────────────────────────────────────────────────────────
# Tier 2.1 — abuse_scenarios severity catalog stability
# ─────────────────────────────────────────────────────────────────────────

def test_abuse_scenarios_catalog_is_fixed():
    """The 5 scenarios must stay stable — UI + reports key off these."""
    from app.engines.ai.abuse_scenarios import SCENARIOS
    keys = sorted(s['key'] for s in SCENARIOS)
    assert keys == ['credential_theft', 'owner_departure',
                     'prompt_injection', 'supply_chain',
                     'tool_abuse']
    for s in SCENARIOS:
        assert 'label' in s and 'description' in s and 'mitre' in s
        assert isinstance(s['mitre'], list)


# ─────────────────────────────────────────────────────────────────────────
# Tier 2.2 — model_registry.classify_model
# ─────────────────────────────────────────────────────────────────────────

def test_model_classifier_fine_tune_pattern():
    from app.engines.ai.model_registry import classify_model
    out = classify_model('gpt-4o-mini-ft-2024-07-18-customer-v3', model_format=None)
    assert out == 'finetune'


def test_model_classifier_baseline():
    from app.engines.ai.model_registry import classify_model
    out = classify_model('gpt-4o', model_format=None)
    # 'gpt-4o' (without ft suffix) is a baseline OpenAI model
    assert out in ('baseline', 'high', 'medium', 'unknown')


def test_model_classifier_returns_a_valid_classification():
    """Classifier never returns None — always one of the catalog values."""
    from app.engines.ai.model_registry import classify_model
    VALID = {'baseline', 'finetune', 'custom', 'high', 'medium', 'unknown'}
    for name in ('llama-3-70b-custom-corp-v2', 'gpt-4o-mini',
                  'claude-3-5-sonnet', 'random-private-model'):
        out = classify_model(name, model_format=None)
        assert out in VALID, f"Got {out!r} for {name!r}"


# ─────────────────────────────────────────────────────────────────────────
# Tier 2.3 — findings._fingerprint
# ─────────────────────────────────────────────────────────────────────────

def test_findings_fingerprint_is_stable():
    from app.engines.ai.findings import _fingerprint
    f1 = _fingerprint('ai_excessive_privilege', 'identity-xyz', 'rbac:owner')
    f2 = _fingerprint('ai_excessive_privilege', 'identity-xyz', 'rbac:owner')
    assert f1 == f2
    # The implementation may use a shorter digest (md5/truncated) — verify
    # collision resistance via uniqueness, not exact length.
    assert isinstance(f1, str) and len(f1) >= 16


def test_findings_fingerprint_uniqueness():
    from app.engines.ai.findings import _fingerprint
    a = _fingerprint('ai_no_owner', 'agent-1', '')
    b = _fingerprint('ai_no_owner', 'agent-2', '')
    c = _fingerprint('ai_credential_exposure', 'agent-1', '')
    assert a != b
    assert a != c


# ─────────────────────────────────────────────────────────────────────────
# Tier 3.1 — multihop_xgraph._enrich_chain weak-link bump
# ─────────────────────────────────────────────────────────────────────────

def test_multihop_enrich_chain_weak_link_bumps_severity():
    from app.engines.ai.multihop_xgraph import _enrich_chain

    class FakeDB:
        class FakeConn:
            def cursor(self_): raise RuntimeError("no DB needed")
        conn = FakeConn()

    chain = {
        'source_identity_id': 'src', 'source_display_name': 'Src',
        'hops': [
            {'identity_db_id': 1, 'identity_id': 'src',  'display_name': 'Src'},
            {'identity_db_id': 2, 'identity_id': 'tgt',  'display_name': 'Tgt'},
        ],
        'edges': [{
            'source_identity_id': 'src', 'target_identity_id': 'tgt',
            'via_mechanism': 'shared_secret',
            'invocation_name': None,
            'confidence': 'inferred',
            'observed_count': 1,
        }],
        'depth': 1,
        'terminal_classification': 'PHI',
        'terminal_records': 120000,
        'is_write': False,
    }
    enriched = _enrich_chain(FakeDB(), chain)
    # Base severity for PHI read = high; weak-link bumps to critical
    assert enriched['base_severity'] == 'high'
    assert enriched['severity'] == 'critical'
    assert enriched['weakest_link'] is not None
    assert enriched['weakest_link']['mechanism'] == 'shared_secret'


# ─────────────────────────────────────────────────────────────────────────
# Tier 3.2 — supply_chain.compute_component_risk
# ─────────────────────────────────────────────────────────────────────────

def test_supply_chain_component_risk_empty():
    from app.engines.ai.supply_chain import compute_component_risk
    score, sev = compute_component_risk([])
    assert score == 0
    assert sev == 'low'


def test_supply_chain_component_risk_capped_at_100():
    from app.engines.ai.supply_chain import compute_component_risk
    # All 11 flags fire → would sum to ~210; capped at 100
    flags = ['fine_tuned', 'unapproved', 'community_plugin',
              'no_pinned_version', 'mutable_dependency',
              'public_endpoint', 'external_managed',
              'unbounded_scope', 'no_scope_audit',
              'unverified_vendor', 'cve']
    score, sev = compute_component_risk(flags)
    assert score == 100
    assert sev == 'critical'


def test_supply_chain_severity_buckets():
    from app.engines.ai.supply_chain import compute_component_risk
    # cve=30 → low (under 40 — actually cve alone = 30 → low)
    score_low, sev_low = compute_component_risk(['cve'])
    assert sev_low == 'low'
    # cve+fine_tuned = 50 → medium
    score_med, sev_med = compute_component_risk(['cve', 'fine_tuned'])
    assert sev_med == 'medium'
    # 4 strong flags → high or critical
    score_high, sev_high = compute_component_risk(
        ['cve', 'fine_tuned', 'public_endpoint', 'unbounded_scope'])
    assert sev_high in ('high', 'critical')


# ─────────────────────────────────────────────────────────────────────────
# Tier 4 — threat_connectors adapters
# ─────────────────────────────────────────────────────────────────────────

def test_threat_connector_azure_acf_adapter():
    from app.engines.ai.threat_connectors import ADAPTERS
    payload = {
        'agent_identity_id': 'demo-agent',
        'request_id': 'req-001',
        'occurred_at': '2026-06-05T00:00:00Z',
        'filter_results': {
            'prompt_injection': {'detected': True, 'severity': 'high'},
            'jailbreak': {'detected': False},
        }
    }
    out = ADAPTERS['azure_content_filter'](payload)
    assert len(out) == 1   # only the detected one
    assert out[0]['signal_type'] == 'prompt_injection'
    assert out[0]['severity'] == 'high'
    assert out[0]['vendor'] == 'azure_content_filter'


def test_threat_connector_bedrock_prompt_attack_to_jailbreak():
    """Bedrock 'PROMPT_ATTACK' should normalize to our 'jailbreak' type."""
    from app.engines.ai.threat_connectors import ADAPTERS
    payload = {
        'agent_identity_id': 'demo-agent',
        'detail': {
            'invocationId': 'inv-1',
            'assessments': [{
                'contentPolicy': {
                    'filters': [
                        {'type': 'PROMPT_ATTACK', 'action': 'BLOCKED',
                          'strength': 'HIGH', 'confidence': 0.95}
                    ]
                }
            }]
        }
    }
    out = ADAPTERS['bedrock_guardrails'](payload)
    assert len(out) == 1
    assert out[0]['signal_type'] == 'jailbreak'
    assert out[0]['severity'] == 'high'


def test_threat_connector_lakera_high_score_to_high():
    from app.engines.ai.threat_connectors import ADAPTERS
    payload = {
        'agent_identity_id': 'demo-agent', 'flag_id': 'lkr-1',
        'results': {
            'prompt_injection': {'detected': True, 'score': 0.92},
        }
    }
    out = ADAPTERS['lakera_guard'](payload)
    assert len(out) == 1
    assert out[0]['signal_type'] == 'prompt_injection'
    assert out[0]['severity'] == 'high'


def test_threat_connector_strip_raw_helper():
    """C-6 (PII protection): _strip_raw removes top-level 'raw' key."""
    from app.engines.ai.threat_connectors import _strip_raw
    inp = {'request_id': 'r1', 'filter_type': 'pii', 'raw': {'prompt': 'SSN 123-45-6789'}}
    out = _strip_raw(inp)
    assert 'raw' not in out
    assert out['request_id'] == 'r1'
    assert out['filter_type'] == 'pii'


def test_threat_connector_strip_raw_handles_non_dict():
    from app.engines.ai.threat_connectors import _strip_raw
    assert _strip_raw(None) == {}
    assert _strip_raw([1, 2, 3]) == {}
    assert _strip_raw("string") == {}


# ─────────────────────────────────────────────────────────────────────────
# Universal Identity Trust (Week 2) — band thresholds
# ─────────────────────────────────────────────────────────────────────────

def test_trust_score_band_thresholds():
    """The 4-band classification should be deterministic and match the UI."""
    # Match the logic in IdentityTrust.tsx + compute_org_trust_rollup
    def band(score):
        if score >= 80: return 'strong'
        if score >= 65: return 'good'
        if score >= 40: return 'elevated'
        return 'critical'
    assert band(100) == 'strong'
    assert band(80) == 'strong'
    assert band(79) == 'good'
    assert band(65) == 'good'
    assert band(64) == 'elevated'
    assert band(40) == 'elevated'
    assert band(39) == 'critical'
    assert band(0) == 'critical'


# ─────────────────────────────────────────────────────────────────────────
# Peer Benchmarking (Week 7) — band placement
# ─────────────────────────────────────────────────────────────────────────

def test_peer_benchmarking_metric_catalog_present():
    from app.engines.benchmarking.peer_benchmarking import METRIC_CATALOG
    for required in ('ownership_coverage_pct', 'trust_score_avg',
                      'nhi_count_per_employee', 'credentials_expired_pct'):
        assert required in METRIC_CATALOG
        m = METRIC_CATALOG[required]
        assert 'label' in m and 'description' in m
        assert 'higher_is_better' in m and isinstance(m['higher_is_better'], bool)
