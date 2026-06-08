/**
 * AuditGraph status page — renders status.json into the page DOM.
 *
 * The status.json file is the source of truth. For pilot phase it's
 * edited by hand; later it'll be updated by an automated monitor
 * (BetterStack / Statuspage.io / custom).
 *
 * Refresh logic: re-fetch status.json every 60s so the page updates
 * automatically without the user reloading. Failures are silent —
 * an unreachable status.json doesn't take the page down.
 */
(function () {
  'use strict';

  const REFRESH_INTERVAL_MS = 60_000;
  const STATUS_LABELS = {
    operational:  'Operational',
    degraded:     'Degraded performance',
    partial:      'Partial outage',
    outage:       'Major outage',
    maintenance:  'Under maintenance',
  };

  const INCIDENT_STATUS_LABELS = {
    investigating: 'Investigating',
    identified:    'Identified',
    monitoring:    'Monitoring',
    resolved:      'Resolved',
  };

  function fmtTime(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      const opts = { year: 'numeric', month: 'short', day: 'numeric',
                     hour: '2-digit', minute: '2-digit', timeZoneName: 'short' };
      return d.toLocaleString(undefined, opts);
    } catch (e) {
      return iso;
    }
  }

  function fmtRelative(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      const diffMs = Date.now() - d.getTime();
      const mins = Math.floor(diffMs / 60_000);
      if (mins < 1) return 'just now';
      if (mins < 60) return `${mins}m ago`;
      const hours = Math.floor(mins / 60);
      if (hours < 24) return `${hours}h ago`;
      const days = Math.floor(hours / 24);
      return `${days}d ago`;
    } catch (e) {
      return '';
    }
  }

  function render(data) {
    // ── Overall hero ──
    const hero = document.getElementById('overall-status');
    const overall = data.overall_status || 'operational';
    hero.className = 'status-hero status-hero--' + overall;
    document.getElementById('overall-headline').textContent =
      data.overall_headline || STATUS_LABELS[overall] || 'Status unknown';
    document.getElementById('overall-detail').innerHTML =
      (data.overall_detail || '') +
      ' Last checked <time datetime="' + (data.last_checked || '') +
      '">' + fmtRelative(data.last_checked) + '</time>.';

    // ── Components ──
    const grid = document.getElementById('component-grid');
    const components = data.components || [];
    grid.innerHTML = components.map(function (c) {
      const status = c.status || 'operational';
      const label = STATUS_LABELS[status] || status;
      return `
        <div class="component">
          <div class="component-info">
            <div class="component-name">${escapeHtml(c.name)}</div>
            <div class="component-desc">${escapeHtml(c.description || '')}</div>
          </div>
          <div class="component-status component-status--${status}">
            <span class="dot"></span>
            <span>${escapeHtml(label)}</span>
          </div>
        </div>
      `;
    }).join('');

    // ── Active incidents ──
    const activeSection = document.getElementById('incidents-active');
    const activeList = document.getElementById('incidents-active-list');
    const active = data.active_incidents || [];
    if (active.length === 0) {
      activeSection.classList.add('hidden');
    } else {
      activeSection.classList.remove('hidden');
      activeList.innerHTML = active.map(renderIncident).join('');
    }

    // ── Past incidents (last 30d) ──
    const pastList = document.getElementById('incidents-past-list');
    const past = data.past_incidents || [];
    if (past.length === 0) {
      pastList.innerHTML = '<p class="muted">No incidents in the last 30 days.</p>';
    } else {
      pastList.innerHTML = past.map(renderIncident).join('');
    }

    // ── Scheduled maintenance ──
    const maintList = document.getElementById('maintenance-list');
    const maintenance = data.scheduled_maintenance || [];
    if (maintenance.length === 0) {
      maintList.innerHTML = '<p class="muted">No maintenance currently scheduled.</p>';
    } else {
      maintList.innerHTML = maintenance.map(renderMaintenance).join('');
    }
  }

  function renderIncident(inc) {
    const status = inc.status || 'investigating';
    const statusLabel = INCIDENT_STATUS_LABELS[status] || status;
    const updates = (inc.updates || []).slice().reverse();  // newest first
    const updatesHtml = updates.map(function (u) {
      return `
        <div class="incident-update">
          <span class="incident-status-tag incident-status-tag--${u.status || status}">${
            INCIDENT_STATUS_LABELS[u.status || status] || u.status || statusLabel}</span>
          <span class="incident-time">${fmtTime(u.at)}</span>
          <div>${escapeHtml(u.message || '')}</div>
        </div>`;
    }).join('');

    const affected = (inc.affected_components || []).join(', ');

    return `
      <div class="incident incident--${status}">
        <div class="incident-header">
          <div class="incident-title">${escapeHtml(inc.title || 'Incident')}</div>
          <div class="incident-time">Started ${fmtTime(inc.started_at)}</div>
        </div>
        ${affected ? `<div class="incident-affected">Affects: ${escapeHtml(affected)}</div>` : ''}
        ${updatesHtml}
      </div>`;
  }

  function renderMaintenance(m) {
    return `
      <div class="incident incident--monitoring">
        <div class="incident-header">
          <div class="incident-title">${escapeHtml(m.title || 'Scheduled maintenance')}</div>
          <div class="incident-time">${fmtTime(m.scheduled_start)} – ${fmtTime(m.scheduled_end)}</div>
        </div>
        ${m.description ? `<div class="incident-update">${escapeHtml(m.description)}</div>` : ''}
      </div>`;
  }

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function load() {
    fetch('status.json?t=' + Date.now(), { cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(render)
      .catch(function (e) {
        console.warn('Failed to load status.json:', e);
      });
  }

  load();
  setInterval(load, REFRESH_INTERVAL_MS);
})();
