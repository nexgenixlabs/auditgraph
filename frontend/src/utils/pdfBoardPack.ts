/**
 * AuditGraph Board Pack PDF generator (2026-06-11)
 *
 * Renders a board-room-ready PDF for the Identity Board Scorecard and the
 * AI Board Scorecard. The user reported that the prior "Download Board Pack"
 * button shipped JSON — fine for a developer round-trip, not what a CISO
 * hands their board.
 *
 * Both scorecards share the same anatomy so we accept a normalized shape:
 *   - cover: title + score + scope + framework chips
 *   - kpi grid: 5-6 percentage KPIs with on-track/at-risk colour
 *   - 30-day trend table (snapshot date + per-KPI columns)
 *   - top risks / worst-N identities table
 *   - recommendations / board callouts
 *
 * Uses the jsPDF + autotable stack already wired in [utils/pdfGenerator.ts].
 */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// Brand palette (matches the dashboards' KPI band colors)
const BRAND       = [79, 70, 229]    as [number, number, number]; // violet-indigo
const SUCCESS     = [16, 185, 129]   as [number, number, number]; // emerald
const WARN        = [245, 158, 11]   as [number, number, number]; // amber
const DANGER      = [239, 68, 68]    as [number, number, number]; // red
const TEXT_DARK   = [15, 23, 42]     as [number, number, number]; // slate-900
const TEXT_GRAY   = [100, 116, 139]  as [number, number, number]; // slate-500
const SURFACE     = [248, 250, 252]  as [number, number, number]; // slate-50

const txt  = (doc: jsPDF, c: [number, number, number]) => doc.setTextColor(c[0], c[1], c[2]);
const fill = (doc: jsPDF, c: [number, number, number]) => doc.setFillColor(c[0], c[1], c[2]);

// ── Common types ───────────────────────────────────────────────────

export interface BoardPackKpi {
  key: string;
  label: string;
  pct: number;            // 0-100
  framework?: string;     // e.g. "NIST AI RMF · Manage 2.1"
  target?: number;        // 0-100 — pass threshold (defaults to 85)
}

export interface BoardPackTrendRow {
  date: string;                // ISO yyyy-mm-dd
  total: number;
  kpis: Record<string, number>; // keyed by BoardPackKpi.key
}

export interface BoardPackTopRow {
  display_name: string;
  identity_type?: string;
  failing_dim?: string;
  owner?: string | null;
  last_seen?: string | null;
  score?: number;
}

export interface BoardPackRecommendation {
  priority: number;            // 1, 2, 3
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail?: string;
  exposure_reduction?: string; // "$1.4M"
}

export interface BoardPackInput {
  reportType: 'Identity Board Scorecard' | 'AI Board Scorecard';
  scopeLabel: string;          // "298 identities in scope" / "13 AI agents in scope"
  generatedAt?: Date;
  clientName?: string;

  // Hero
  scoreLabel: string;          // "Identity Security Score" / "AI Governance Score"
  scoreValue: number;          // 0-100
  scoreBand: string;           // "Elevated" / "Good"
  scorePrior?: number | null;  // 30d-prior score for delta line
  exposureReduction?: string;  // "$2.4M exposure reduction available"

  // KPIs (5-6 rows in the table)
  kpis: BoardPackKpi[];

  // Trend table
  trend: BoardPackTrendRow[];

  // Top risks (worst N identities/agents)
  topRisks: BoardPackTopRow[];

  // Board recommendations
  recommendations: BoardPackRecommendation[];

  // Frameworks attestation row
  frameworks: string[];
}

// ── Helpers ────────────────────────────────────────────────────────

function bandColor(pct: number, target = 85): [number, number, number] {
  if (pct >= target) return SUCCESS;
  if (pct >= Math.max(0, target - 20)) return WARN;
  return DANGER;
}

function severityColor(sev: BoardPackRecommendation['severity']): [number, number, number] {
  return sev === 'critical' ? DANGER : sev === 'high' ? [251, 146, 60] : sev === 'medium' ? WARN : SUCCESS;
}

function fmtDate(d: Date): string {
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

function fmtShort(d: string): string {
  try { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }); }
  catch { return d; }
}

// ── Generator ──────────────────────────────────────────────────────

export function generateBoardPack(pack: BoardPackInput): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 18;
  const contentW = pageW - margin * 2;
  const stamp = (pack.generatedAt || new Date()).toISOString().slice(0, 10);

  // ── Cover band ──────────────────────────────────────────────────
  fill(doc, BRAND);
  doc.rect(0, 0, pageW, 60, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditGraph', margin, 28);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(pack.reportType, margin, 38);
  doc.setFontSize(9);
  doc.text(`Generated ${fmtDate(pack.generatedAt || new Date())}`, margin, 47);
  if (pack.clientName) doc.text(`Prepared for ${pack.clientName}`, margin, 53);

  // ── Hero score panel ────────────────────────────────────────────
  let y = 76;
  fill(doc, SURFACE);
  doc.roundedRect(margin, y, contentW, 36, 3, 3, 'F');
  txt(doc, TEXT_GRAY);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.text(pack.scoreLabel.toUpperCase(), margin + 6, y + 9);

  const scoreCol = bandColor(pack.scoreValue);
  txt(doc, scoreCol);
  doc.setFontSize(32);
  doc.setFont('helvetica', 'bold');
  doc.text(`${pack.scoreValue}`, margin + 6, y + 26);

  txt(doc, TEXT_DARK);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(`/100  ·  ${pack.scoreBand}`, margin + 35, y + 26);

  txt(doc, TEXT_GRAY);
  doc.setFontSize(9);
  doc.text(pack.scopeLabel, margin + 6, y + 32);

  // Delta line on right
  if (pack.scorePrior != null) {
    const delta = pack.scoreValue - pack.scorePrior;
    const arrow = delta > 0 ? '↑' : delta < 0 ? '↓' : '→';
    const dCol = delta > 0 ? SUCCESS : delta < 0 ? DANGER : TEXT_GRAY;
    txt(doc, dCol);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`${arrow} ${Math.abs(delta)} pts vs 30d ago`, pageW - margin - 6, y + 18, { align: 'right' });
  }
  if (pack.exposureReduction) {
    txt(doc, TEXT_GRAY);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(pack.exposureReduction, pageW - margin - 6, y + 28, { align: 'right' });
  }
  y += 44;

  // ── KPI table ───────────────────────────────────────────────────
  autoTable(doc, {
    startY: y,
    head: [['KPI', 'Coverage', 'Target', 'Framework', 'Status']],
    body: pack.kpis.map(k => {
      const target = k.target ?? 85;
      const status = k.pct >= target ? 'On track' : k.pct >= target - 20 ? 'At risk' : 'Critical';
      return [k.label, `${Math.round(k.pct)}%`, `${target}%`, k.framework || '—', status];
    }),
    margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 3 },
    headStyles: { fillColor: TEXT_DARK, textColor: [255, 255, 255], fontStyle: 'bold' },
    alternateRowStyles: { fillColor: SURFACE },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 4) {
        const text = String(data.cell.raw || '');
        const color = text === 'On track' ? SUCCESS : text === 'At risk' ? WARN : DANGER;
        data.cell.styles.textColor = color;
        data.cell.styles.fontStyle = 'bold';
      }
    },
  });
  y = (doc as any).lastAutoTable.finalY + 8;

  // ── Trend table (compressed) ───────────────────────────────────
  if (pack.trend.length > 0) {
    txt(doc, TEXT_DARK);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('30-Day Trend', margin, y);
    y += 3;

    // Pivot trend: each KPI as a row, columns are sampled snapshot dates (5 cols max).
    const sample = (() => {
      const n = pack.trend.length;
      if (n <= 5) return pack.trend;
      const idxs = [0, Math.floor(n * 0.25), Math.floor(n * 0.5), Math.floor(n * 0.75), n - 1];
      return idxs.map(i => pack.trend[i]);
    })();

    const head = [['KPI', ...sample.map(r => fmtShort(r.date))]];
    const body = pack.kpis.map(k => [
      k.label,
      ...sample.map(r => `${Math.round(r.kpis[k.key] ?? 0)}%`),
    ]);
    autoTable(doc, {
      startY: y + 2,
      head, body,
      margin: { left: margin, right: margin },
      styles: { fontSize: 8.5, cellPadding: 2.5 },
      headStyles: { fillColor: BRAND, textColor: [255, 255, 255] },
      alternateRowStyles: { fillColor: SURFACE },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // ── New page if needed ────────────────────────────────────────
  const pageH = doc.internal.pageSize.getHeight();
  if (y > pageH - 80) { doc.addPage(); y = margin; }

  // ── Top risks ──────────────────────────────────────────────────
  if (pack.topRisks.length > 0) {
    txt(doc, TEXT_DARK);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(pack.reportType === 'AI Board Scorecard' ? 'Top 10 AI Risks' : 'Top 10 Critical Identities', margin, y);
    y += 3;

    autoTable(doc, {
      startY: y + 2,
      head: [['Identity', 'Type', 'Failing Dimension', 'Owner', 'Last Seen', 'Score']],
      body: pack.topRisks.slice(0, 10).map(r => [
        r.display_name,
        r.identity_type || '—',
        r.failing_dim || '—',
        r.owner || '—',
        r.last_seen || '—',
        typeof r.score === 'number' ? `${r.score}` : '—',
      ]),
      margin: { left: margin, right: margin },
      styles: { fontSize: 8.5, cellPadding: 2.5 },
      headStyles: { fillColor: TEXT_DARK, textColor: [255, 255, 255] },
      alternateRowStyles: { fillColor: SURFACE },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  if (y > pageH - 80) { doc.addPage(); y = margin; }

  // ── Board recommendations ─────────────────────────────────────
  if (pack.recommendations.length > 0) {
    txt(doc, TEXT_DARK);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Board Recommendations', margin, y);
    y += 6;

    pack.recommendations.slice(0, 5).forEach((rec) => {
      const cardH = rec.detail ? 22 : 16;
      if (y + cardH > pageH - 30) { doc.addPage(); y = margin; }
      const sevCol = severityColor(rec.severity);
      fill(doc, SURFACE);
      doc.roundedRect(margin, y, contentW, cardH, 2, 2, 'F');
      // Priority chip
      fill(doc, sevCol);
      doc.roundedRect(margin + 4, y + 4, 16, 8, 1.5, 1.5, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text(`P${rec.priority}`, margin + 12, y + 9.5, { align: 'center' });
      // Severity chip
      fill(doc, sevCol);
      doc.roundedRect(margin + 22, y + 4, 22, 8, 1.5, 1.5, 'F');
      doc.text(rec.severity.toUpperCase(), margin + 33, y + 9.5, { align: 'center' });

      // Title
      txt(doc, TEXT_DARK);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(rec.title, margin + 50, y + 9);

      // Detail
      if (rec.detail) {
        txt(doc, TEXT_GRAY);
        doc.setFontSize(8.5);
        doc.setFont('helvetica', 'normal');
        const wrapped = doc.splitTextToSize(rec.detail, contentW - 60);
        doc.text(wrapped, margin + 50, y + 15);
      }

      // Exposure reduction on right
      if (rec.exposure_reduction) {
        txt(doc, SUCCESS);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(rec.exposure_reduction, pageW - margin - 4, y + 9, { align: 'right' });
        txt(doc, TEXT_GRAY);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'normal');
        doc.text('exposure reduction', pageW - margin - 4, y + 13, { align: 'right' });
      }
      y += cardH + 4;
    });
  }

  // ── Footer on every page ──────────────────────────────────────
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    txt(doc, TEXT_GRAY);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(
      `${pack.reportType} · Architecture-derived · ${pack.frameworks.join(' · ')}`,
      margin, pageH - 8
    );
    doc.text(`Page ${i} of ${pageCount}`, pageW - margin, pageH - 8, { align: 'right' });
  }

  // ── Save ──────────────────────────────────────────────────────
  const slug = pack.reportType === 'AI Board Scorecard' ? 'ai-board-pack' : 'identity-board-pack';
  doc.save(`auditgraph-${slug}-${stamp}.pdf`);
}

// ── CSV export (alternative format) ────────────────────────────────

export function exportBoardPackCsv(pack: BoardPackInput): void {
  const lines: string[] = [];
  lines.push(`# ${pack.reportType}`);
  lines.push(`# Generated: ${(pack.generatedAt || new Date()).toISOString()}`);
  lines.push(`# Scope: ${pack.scopeLabel}`);
  lines.push(`# ${pack.scoreLabel}: ${pack.scoreValue} (${pack.scoreBand})`);
  lines.push('');
  lines.push('## KPIs');
  lines.push('KPI,Coverage %,Target %,Framework,Status');
  pack.kpis.forEach(k => {
    const target = k.target ?? 85;
    const status = k.pct >= target ? 'On track' : k.pct >= target - 20 ? 'At risk' : 'Critical';
    lines.push(`"${k.label}",${Math.round(k.pct)},${target},"${k.framework || ''}","${status}"`);
  });
  lines.push('');
  lines.push('## 30-Day Trend');
  const trendHead = ['Date', 'Total', ...pack.kpis.map(k => k.label)];
  lines.push(trendHead.join(','));
  pack.trend.forEach(t => {
    const row = [t.date, t.total, ...pack.kpis.map(k => Math.round(t.kpis[k.key] ?? 0))];
    lines.push(row.join(','));
  });
  lines.push('');
  lines.push('## Top Risks');
  lines.push('Identity,Type,Failing Dimension,Owner,Last Seen,Score');
  pack.topRisks.forEach(r => {
    lines.push(`"${r.display_name}","${r.identity_type || ''}","${r.failing_dim || ''}","${r.owner || ''}","${r.last_seen || ''}",${r.score ?? ''}`);
  });
  lines.push('');
  lines.push('## Board Recommendations');
  lines.push('Priority,Severity,Title,Detail,Exposure Reduction');
  pack.recommendations.forEach(r => {
    const detail = (r.detail || '').replace(/"/g, '""');
    lines.push(`P${r.priority},${r.severity},"${r.title}","${detail}","${r.exposure_reduction || ''}"`);
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = (pack.generatedAt || new Date()).toISOString().slice(0, 10);
  const slug = pack.reportType === 'AI Board Scorecard' ? 'ai-board-pack' : 'identity-board-pack';
  a.href = url;
  a.download = `auditgraph-${slug}-${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
