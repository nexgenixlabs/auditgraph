# Screen Walkthrough — Peer Benchmarking

**Route**: `/peer-benchmarking` · **Section**: Governance & Assurance · **Audience**: CISOs, board members, GRC

## What this screen answers

> *"How does my identity security posture compare to peer organizations in my industry and size?"*

Peer Benchmarking shows your tenant's metrics next to anonymized percentile bands from peers in the same industry and org size. It answers the second question every board asks (after "how much risk do we have?") — *"how does that compare?"* — with defensible, source-cited comparison data.

## What you see on screen

### Top — industry + size selector

Two chip rows:

- Industry: tech · healthcare · financial_services · retail
- Size: SMB (<500) · Mid (500-5K) · Enterprise (5K-50K)

Pick your industry and size to scope the comparison. Aggregates require at least 10 contributing organizations per bucket; smaller buckets show "Insufficient peers" rather than fabricating a sample.

### Headline card

> *"3 of 6 tracked metrics put you in the top quartile. 2 in the bottom quartile."*

The single sentence summary for a board slide.

### Per-metric cards (6)

One card per tracked metric. Each card shows:

- Metric label + description
- Your value (large, color-coded to band)
- Peer median
- Sample size (n=N)
- **Higher/lower is better** indicator
- **Percentile distribution bar** with your position marked

### Tracked metrics

| Metric | Higher is better? | What it captures |
|---|---|---|
| **Owner coverage** | Yes | Percent of NHIs with active human owner |
| **Mean Identity Trust** | Yes | Average Trust Score across NHIs (0-100) |
| **NHIs per employee** | No | Ratio of NHIs to humans (lower = leaner identity footprint) |
| **Expired credentials** | No | Percent of NHIs with expired credentials |
| **AI share of NHI** | No | Percent of NHIs that are AI-classified (high % = AI sprawl) |
| **Un-triaged findings** | No | Percent of findings without triage decision |

The "lower is better" interpretation matters — the band placement flips accordingly. Being in the top 10% for *un-triaged findings* means you have a low percent of un-triaged findings (you're triaging promptly), which is good.

### Percentile bar (visual)

Each metric's bar shows the p10 / p25 / p50 / p75 / p90 boundaries with a white dot marking your value. The bar coloring (red → orange → amber → blue → green) makes worse-to-better visually obvious.

### Per-card narrative

> *"You're in the **top 10%** of peers — keep it up. Your Owner coverage is 16.5 points higher than the median (better)."*

The narrative is generated from the band placement and the distance from median. Tone shifts when you're in the bottom quartile: *"Bottom quartile — peers are doing better."*

## How peer data is computed

Each customer's tenant runs a nightly snapshot job that writes their current values to `peer_benchmark_snapshots` (RLS-protected, tenant-isolated). The aggregator reads across all snapshots, buckets by (industry, org_size_band, metric_key, snapshot_date), and computes percentile boundaries (p10, p25, p50, p75, p90) when at least 10 distinct organizations have contributed to the bucket.

The aggregates are stored in `peer_benchmark_aggregates` with no tenant scope (public read for all customers in the bucket). Raw per-org values are never visible to anyone other than the contributing org.

### Privacy guarantees

- **Snapshots are tenant-isolated**: A customer can only see their own raw values. The aggregator runs with admin DB access for cross-tenant SELECT during nightly job execution.
- **Aggregates are anonymized**: Each bucket aggregates ≥10 contributors. The percentile values can't be reverse-engineered to a single org.
- **Differential privacy on small buckets**: Buckets with n=10-19 receive Laplace noise (epsilon=1.0) on the boundaries before storage. Larger buckets are exact.
- **Industry skew**: The buckets are pre-skewed by domain knowledge (healthcare typically worse on findings triage, finance worse on credential rotation, tech worse on AI sprawl) to reflect real-world distributions.

## Demo data

For the demo (org=3 on dev-cloud), 1080 synthetic peer snapshots are seeded into the tech/mid bucket. This is the only environment with synthetic data — production tenants only see real anonymized aggregates.

The demo numbers tell a clear story:

| Metric | Demo org=3 | Peer median (tech/mid) | Band |
|---|---|---|---|
| Owner coverage | 0% | 57.5% | Bottom 10% |
| Mean Identity Trust | 65 | 62 | Above median |
| NHIs per employee | 0.95 | 2.65 | Top 10% |
| Expired credentials | 0% | 14% | Top 10% |
| AI share of NHI | 8.72% | 17.5% | Top 10% |
| Un-triaged findings | 100% | 40% | Bottom 10% |

Narrative: *"top-10% in 4 of 6 categories, but bottom-10% on owner coverage (0%) and finding triage (100% un-triaged). Open Ownership Center to start closing the gap."*

This is the exact framing that drives renewals — peers see exactly where they're winning and where they're losing, and the next click (Ownership Center) is the workflow to fix the worst gap.

## How this is a moat

Peer benchmarking is a **network effect** — every new customer that contributes a snapshot makes the next customer's demo more compelling. A startup competitor can't replicate this without a customer base. Per the peer review v3, *"the peer benchmarking page may become more valuable than patents over time."*

This is why the network effect matters more than the algorithm: anyone can implement percentile calculations; nobody can buy a customer base.

## Common questions

**Q: My bucket says "Insufficient peers." When will I see data?**
Once 10 distinct customers in your industry+size combination have run snapshots. The bootstrapping period — until that threshold is reached — shows your own values without comparison.

**Q: How do I know the peers in my bucket are similar to me?**
The buckets are coarse (industry × size). For tighter cohorts (e.g., "healthcare orgs >5K employees on Azure with > 50 AI agents"), the algorithm would need finer bucketing. Today, industry + size is the level customers consistently understand and value.

**Q: Can my data be reverse-engineered out of the aggregates?**
For n ≥ 20, no — the boundaries are too aggregate. For n in 10-19, Laplace noise is applied. Below 10, no aggregate is published.

**Q: Do you compare us across time?**
Yes — the snapshot_date dimension allows trend analysis. The current UI shows the most recent snapshot; a forthcoming trend view will show your percentile band over time (are you climbing or falling).

## What to do next

1. Pick your industry + size. Note which bands you're in.
2. For each bottom-quartile metric, click through to the relevant remediation screen (Ownership Center for owner coverage, AI Findings for triage backlog, etc.).
3. After your next snapshot (typically daily), re-check. Watch the bands shift.
4. Take a screenshot of your top-quartile metrics for the next board pack.

## Related screens

- [Identity Trust](#screen-identity-trust) — drives the "Mean Identity Trust" metric
- [Ownership Center](#screen-ownership-center) — drives the "Owner coverage" metric
- [AI Findings](#screen-ai-findings) — drives the "Un-triaged findings" metric
