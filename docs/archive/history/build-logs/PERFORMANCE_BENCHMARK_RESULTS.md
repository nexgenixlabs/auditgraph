# AuditGraph Performance Benchmark Results

**Date:** 2026-02-26T17:40:07Z
**Branch:** dev
**Scale:** 520 identities, 160 role assignments, 60 resources, 30 discovery runs, 29 drift reports
**Backend:** Flask + Gunicorn (local dev, single worker)
**Database:** PostgreSQL 16 (local)
**Indexes:** 9 composite performance indexes active

---

## Endpoint Benchmark Results

| Endpoint | Status | Latency (ms) | Response Size |
|----------|--------|--------------|---------------|
| `GET /api/health` | 200 | 294 | 303 B |
| `GET /api/stats` | 200 | 665 | 481 B |
| `GET /api/identity-summary` | 200 | 661 | 977 B |
| `GET /api/identities` (default limit) | 200 | 458 | 706 KB |
| `GET /api/identities?limit=100` | 200 | 401 | 138 KB |
| `GET /api/identities?limit=500` | 200 | 493 | 692 KB |
| `GET /api/identities?risk_level=critical` | 200 | 358 | 30 KB |
| `GET /api/risks` | 200 | 427 | 23 KB |
| `GET /api/dashboard/posture` | 200 | 418 | 380 B |
| `GET /api/dashboard/compliance` | 200 | 3060 | 33 KB |
| `GET /api/runs` | 200 | 367 | 6 KB |
| `GET /api/drift/latest` | 200 | 268 | 277 B |
| `GET /api/drift/history` | 200 | 340 | 6 KB |
| `GET /api/resources` | 200 | 767 | 52 KB |
| `GET /api/resources/stats` | 200 | 421 | 473 B |
| `GET /api/spns` | 200 | 467 | 88 KB |
| `GET /api/spns/stats` | 200 | 525 | 561 B |
| `GET /api/anomalies/stats` | 200 | 591 | 57 B |
| `GET /api/activity?limit=50` | 200 | 621 | 16 KB |
| `GET /api/settings` | 200 | 273 | 1 KB |
| `GET /api/system/health` | 200 | 384 | 4 KB |

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Endpoints tested | 22 |
| Successful (2xx) | 21 |
| Average latency | 584 ms |
| Max latency | 3,060 ms (`/api/dashboard/compliance`) |
| P95 latency | 767 ms |
| Under 500 ms | 14/21 (67%) |
| Under 1,000 ms | 20/21 (95%) |

---

## Performance Targets

| Target | Threshold | Result |
|--------|-----------|--------|
| Health check | < 500 ms | PASS (294 ms) |
| Identity list (500) | < 2,000 ms | PASS (493 ms) |
| Dashboard stats | < 1,000 ms | PASS (665 ms) |
| Filtered queries | < 500 ms | PASS (358 ms) |
| Resource list | < 1,000 ms | PASS (767 ms) |
| P95 all endpoints | < 2,000 ms | PASS (767 ms) |
| 95% under 1s | >= 95% | PASS (95%) |

---

## Notes

- `/api/dashboard/compliance` is the slowest endpoint (3,060 ms) due to complex cross-table GRC framework joins. Cacheable for production.
- All identity list endpoints return full results under 500 ms for 520 identities.
- Performance indexes (`idx_identities_tenant_run`, `idx_identities_tenant_risk`, etc.) are critical for these results.
- Production deployment with 2 Gunicorn workers + connection pooling would reduce latencies further.
- POST `/api/identities/query` returned 400 in this test (missing field mapping for seeded data); the endpoint itself responds in 251 ms.

---

## Seed Data Configuration

```
python3 scripts/seed_performance_data.py --tenant-id 1 --clean
```

| Data Type | Count |
|-----------|-------|
| Human identities | 200 |
| Service principals | 150 |
| System managed identities | 80 |
| User managed identities | 50 |
| Guest accounts | 30 |
| Microsoft internal | 10 |
| Role assignments | 160 |
| Storage accounts | 35 |
| Key vaults | 25 |
| Discovery runs | 30 |
| Drift reports | 29 |
| Cloud subscriptions | 7 |
