"""Argus — AI Identity Security Analyst.

The 7-layer Copilot framework (AG-184 ARGUS EPIC). Each layer is a
dedicated engine module that reasons over the identity graph:

  L1 Natural Language Investigation     argus_nl_query.py        (AG-185)
  L2 Security Reasoning                 argus_reasoner.py        (AG-186)
  L3 Attack Path Investigator           attack_path_investigator.py (AG-187, this commit)
  L4 Board/CISO Advisor                 ciso_advisor.py          (AG-188)
  L5 Explain Why                        explain_risk_score.py    (AG-189)
  L6 What-If Simulator                  what_if.py               (AG-190, this commit)
  L7 Executive Storytelling             exec_narrative.py        (AG-191)
  XGRAPH Cross-identity reasoning       cross_graph.py           (AG-192)

All Argus engines:
  - Cite the graph evidence used (no LLM hallucination — direct queries).
  - Cache results to a dedicated cache table keyed by (query_hash, tenant, latest_run).
  - Respect org_id RLS scoping.
  - Honor "no fake answers" — return None/found:false when nothing matches.
"""
