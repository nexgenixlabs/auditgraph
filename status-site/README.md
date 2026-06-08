# AuditGraph Status Page

Public-facing status page hosted at `status.auditgraph.ai`.

**Hosted separately from the main app** (Cloudflare Pages, separate edge) so
this page stays available even during platform incidents. That's the entire
reason a status page exists.

## Architecture

Pure static site. No server-side rendering, no backend. Single file
(`status.json`) drives the entire page; `app.js` renders it client-side
and refreshes every 60 seconds.

```
status-site/
├── index.html        ← page shell
├── style.css         ← styling (same dark palette as docs.auditgraph.ai)
├── app.js            ← renders status.json into the DOM
├── status.json       ← source of truth — edit this to update the page
├── _headers          ← Cloudflare Pages: security + cache headers
├── _redirects        ← Cloudflare Pages: SPA fallback
└── README.md         ← this file
```

## How to declare an incident

Edit `status.json` directly. Push to `main`. Cloudflare auto-deploys in
~30 seconds.

### Step 1 — when the incident starts

1. Add an entry to `active_incidents`:
   ```json
   {
     "id": "INC-2026-06-08-001",
     "title": "Elevated API response times on identity list",
     "status": "investigating",
     "severity": "minor",
     "started_at": "2026-06-08T14:23:00Z",
     "resolved_at": null,
     "affected_components": ["api"],
     "updates": [
       {
         "at": "2026-06-08T14:25:00Z",
         "status": "investigating",
         "message": "We're investigating reports of slow responses on /api/identities."
       }
     ]
   }
   ```

2. Update the affected `components[]` status from `operational` to one of:
   - `degraded` — slow but functional
   - `partial` — some users affected, some unaffected
   - `outage` — fully down

3. Update `overall_status` + `overall_headline`:
   ```json
   "overall_status": "degraded",
   "overall_headline": "API experiencing elevated response times",
   "overall_detail": "We're investigating slow responses on identity list endpoints."
   ```

4. Commit + push to `main`. Live in ~30 seconds.

### Step 2 — provide updates during the incident

Append a new entry to the incident's `updates[]` array. Newer entries are
shown first by the renderer. Update the incident's `status` field as you
move through the lifecycle:

```
investigating  ← we know something is wrong, still finding root cause
    ↓
identified     ← root cause identified
    ↓
monitoring     ← fix deployed, watching to confirm
    ↓
resolved       ← confirmed fully resolved
```

### Step 3 — when the incident is resolved

1. Move the incident from `active_incidents` to `past_incidents`
2. Set `status: "resolved"` and `resolved_at`
3. Add a final `update` entry summarizing the cause + fix
4. Restore each affected component to `operational`
5. Restore `overall_status` to `operational`
6. Commit + push

### Step 4 — clean up old incidents

The page shows the last 30 days of incidents. After 30 days, move the
entry to `archived_incidents` or delete it (the page won't render either way).

## How to schedule maintenance

Add to `scheduled_maintenance[]`:

```json
{
  "title": "PostgreSQL upgrade to v17",
  "description": "Brief 5-minute API downtime during the upgrade window.",
  "scheduled_start": "2026-06-15T02:00:00Z",
  "scheduled_end":   "2026-06-15T02:30:00Z",
  "affected_components": ["api", "discovery"]
}
```

Remove when complete.

## Future automation

For pilot phase, this page is updated by hand. After 5+ pilots or any 24/7
operation:

- Hook up uptime checks (Cronitor, Healthchecks.io) to auto-update component
  status on detected outages
- Email-on-incident via SendGrid + a small Worker that watches `status.json`
- Auto-generated post-mortems from the `updates[]` history

These are quality-of-life improvements, not required for pilot phase.

## Deploy

Same Cloudflare Pages pattern as `docs.auditgraph.ai`:

1. Cloudflare dashboard → Pages → Create project → Connect Git
2. Repo: `nexgenixlabs/auditgraph`
3. Production branch: `main`
4. Framework preset: None
5. Build command: (leave empty)
6. **Build output directory: `status-site`**
7. Root directory: `/`
8. Save and Deploy
9. Custom domain: `status.auditgraph.ai` → CNAME to `<project>.pages.dev`

Cloudflare provisions TLS automatically. Every push to `main` re-deploys.
