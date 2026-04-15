/**
 * AuditGraph PDF Report Generator
 *
 * Generates professional security audit reports using jsPDF + autotable.
 * Called from the Reports page with data from /api/reports/data.
 */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { TIME_MS } from '../constants/metrics';

// Extend jsPDF type for autotable
declare module 'jspdf' {
  interface jsPDF {
    lastAutoTable: { finalY: number };
  }
}

interface ReportData {
  generated_at: string;
  run_id: number;
  collected_at: string | null;
  stats: {
    total_identities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  previous_run?: {
    total_identities: number;
    critical: number;
    high: number;
  } | null;
  credential_health: {
    expired: number;
    expiring_soon: number;
    healthy: number;
    unknown: number;
  };
  conditional_access: {
    covered: number;
    not_covered: number;
    total: number;
  };
  top_risks: {
    identity_id: string;
    display_name: string;
    identity_category: string;
    risk_level: string;
    risk_score: number;
    risk_reasons: string[];
    remediations: {
      title: string;
      impact: string;
      effort: string;
      steps: string[];
      compliance_refs: string[];
    }[];
  }[];
  remediation_summary: {
    total_actions: number;
    by_category: Record<string, number>;
    by_impact: Record<string, number>;
    quick_wins: {
      title: string;
      impact: string;
      effort: string;
      affected_identities: number;
    }[];
    top_priorities: {
      title: string;
      impact: string;
      effort: string;
      priority_score: number;
      affected_identities: number;
      compliance_refs: string[];
    }[];
  };
  evidence: {
    sources: Record<string, string>;
  };
}

// Colors (tuple types for jsPDF)
type RGB = [number, number, number];
const BLUE: RGB = [37, 99, 235];       // brand blue
const DARK: RGB = [17, 24, 39];        // gray-900
const GRAY: RGB = [107, 114, 128];     // gray-500
const RED: RGB = [220, 38, 38];        // red-600
const ORANGE: RGB = [234, 88, 12];     // orange-600
const GREEN: RGB = [22, 163, 74];      // green-600

function riskColor(level: string): RGB {
  switch (level?.toLowerCase()) {
    case 'critical': return RED;
    case 'high': return ORANGE;
    case 'medium': return [202, 138, 4]; // yellow-600
    case 'low': return GREEN;
    default: return GRAY;
  }
}

// Helpers to avoid TS spread errors with jsPDF tuple params
function fill(doc: jsPDF, c: RGB) { doc.setFillColor(c[0], c[1], c[2]); }
function txt(doc: jsPDF, c: RGB) { doc.setTextColor(c[0], c[1], c[2]); }
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function draw(doc: jsPDF, c: RGB) { doc.setDrawColor(c[0], c[1], c[2]); }

export function generateReport(data: ReportData, clientName?: string): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;

  // ═══════════════════════════════════════════
  // PAGE 1: Cover
  // ═══════════════════════════════════════════
  // Blue header band
  fill(doc, BLUE);
  doc.rect(0, 0, pageWidth, 80, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditGraph', margin, 35);

  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text('Identity Security Audit Report', margin, 48);

  doc.setFontSize(9);
  doc.text('Map. Monitor. Secure.', margin, 58);

  // Client info block
  txt(doc, DARK);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(clientName || 'Security Audit Report', margin, 105);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  txt(doc, GRAY);
  const reportDate = new Date(data.generated_at).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric'
  });
  doc.text(`Generated: ${reportDate}`, margin, 115);
  doc.text(`Snapshot: #${data.run_id}`, margin, 122);
  if (data.collected_at) {
    doc.text(`Data Collected: ${new Date(data.collected_at).toLocaleString()}`, margin, 129);
  }

  // Stats summary on cover
  const statsY = 155;
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Snapshot Summary', margin, statsY);

  const statsData = [
    ['Total Identities', String(data.stats.total_identities)],
    ['Critical Risk', String(data.stats.critical)],
    ['High Risk', String(data.stats.high)],
    ['Medium Risk', String(data.stats.medium)],
    ['Low Risk', String(data.stats.low)],
  ];

  autoTable(doc, {
    startY: statsY + 5,
    head: [['Metric', 'Count']],
    body: statsData,
    theme: 'grid',
    headStyles: { fillColor: BLUE, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9, textColor: DARK },
    columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 30, halign: 'center' } },
    margin: { left: margin, right: margin },
    tableWidth: 100,
  });

  // Trend comparison
  if (data.previous_run) {
    const trendY = (doc as any).lastAutoTable.finalY + 10;
    doc.setFontSize(9);
    txt(doc, GRAY);
    const critDelta = data.stats.critical - data.previous_run.critical;
    const highDelta = data.stats.high - data.previous_run.high;
    const trendText = `Trend vs previous snapshot: Critical ${critDelta >= 0 ? '+' : ''}${critDelta}, High ${highDelta >= 0 ? '+' : ''}${highDelta}`;
    doc.text(trendText, margin, trendY);
  }

  // Footer
  addFooter(doc, 1);

  // ═══════════════════════════════════════════
  // PAGE 2: Executive Summary
  // ═══════════════════════════════════════════
  doc.addPage();
  let y = addHeader(doc, 'Executive Summary', margin);

  // Posture metrics
  const total = data.stats.total_identities || 1;
  const highRisk = data.stats.critical + data.stats.high + data.stats.medium;
  const postureScore = Math.round(((total - highRisk) / total) * 100);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Security Posture Score', margin, y);
  y += 8;

  // Score bar
  doc.setFillColor(229, 231, 235); // gray-200
  doc.roundedRect(margin, y, contentWidth, 8, 2, 2, 'F');
  const scoreColor = postureScore >= 70 ? GREEN : postureScore >= 40 ? ORANGE : RED;
  fill(doc, scoreColor);
  doc.roundedRect(margin, y, contentWidth * (postureScore / 100), 8, 2, 2, 'F');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text(`${postureScore}%`, margin + 4, y + 5.5);
  y += 16;

  // Risk breakdown
  txt(doc, DARK);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Risk Distribution', margin, y);
  y += 5;

  const riskRows = [
    ['Critical', String(data.stats.critical), `${Math.round((data.stats.critical / total) * 100)}%`],
    ['High', String(data.stats.high), `${Math.round((data.stats.high / total) * 100)}%`],
    ['Medium', String(data.stats.medium), `${Math.round((data.stats.medium / total) * 100)}%`],
    ['Low', String(data.stats.low), `${Math.round((data.stats.low / total) * 100)}%`],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Risk Level', 'Count', '% of Total']],
    body: riskRows,
    theme: 'striped',
    headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: margin, right: margin },
    tableWidth: 120,
    didParseCell(hookData) {
      if (hookData.section === 'body' && hookData.column.index === 0) {
        const level = hookData.cell.raw as string;
        hookData.cell.styles.textColor = riskColor(level);
        hookData.cell.styles.fontStyle = 'bold';
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  // Credential health
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Credential Health', margin, y);
  y += 5;

  const credRows = [
    ['Expired', String(data.credential_health.expired)],
    ['Expiring (<30d)', String(data.credential_health.expiring_soon)],
    ['Healthy', String(data.credential_health.healthy)],
    ['Unknown', String(data.credential_health.unknown)],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Status', 'Count']],
    body: credRows,
    theme: 'striped',
    headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: margin, right: margin },
    tableWidth: 100,
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  // Conditional Access
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Conditional Access Coverage', margin, y);
  y += 5;

  const caTotal = data.conditional_access.total || 1;
  const caPct = Math.round((data.conditional_access.covered / caTotal) * 100);

  autoTable(doc, {
    startY: y,
    head: [['Status', 'Count', '%']],
    body: [
      ['Covered', String(data.conditional_access.covered), `${caPct}%`],
      ['Not Covered', String(data.conditional_access.not_covered), `${100 - caPct}%`],
    ],
    theme: 'striped',
    headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: margin, right: margin },
    tableWidth: 100,
  });

  addFooter(doc, 2);

  // ═══════════════════════════════════════════
  // PAGE 3+: Top Risks
  // ═══════════════════════════════════════════
  doc.addPage();
  y = addHeader(doc, 'Top Risk Identities', margin);

  const riskTableData = data.top_risks.map(tr => [
    tr.display_name.length > 30 ? tr.display_name.substring(0, 27) + '...' : tr.display_name,
    (tr.risk_level || '').toUpperCase(),
    String(tr.risk_score),
    (tr.risk_reasons || []).slice(0, 2).join('; ').substring(0, 60),
    tr.remediations.length > 0 ? tr.remediations[0].title.substring(0, 40) : 'None',
  ]);

  autoTable(doc, {
    startY: y,
    head: [['Identity', 'Risk', 'Score', 'Top Risk Reasons', 'Priority Remediation']],
    body: riskTableData,
    theme: 'striped',
    headStyles: { fillColor: BLUE, textColor: [255, 255, 255], fontSize: 8 },
    bodyStyles: { fontSize: 7 },
    columnStyles: {
      0: { cellWidth: 35 },
      1: { cellWidth: 15, halign: 'center' },
      2: { cellWidth: 15, halign: 'center' },
      3: { cellWidth: 55 },
      4: { cellWidth: 45 },
    },
    margin: { left: margin, right: margin },
    didParseCell(hookData) {
      if (hookData.section === 'body' && hookData.column.index === 1) {
        const level = (hookData.cell.raw as string).toLowerCase();
        hookData.cell.styles.textColor = riskColor(level);
        hookData.cell.styles.fontStyle = 'bold';
      }
    },
  });

  addFooter(doc, 3);

  // ═══════════════════════════════════════════
  // PAGE 4+: Remediation Playbook
  // ═══════════════════════════════════════════
  doc.addPage();
  y = addHeader(doc, 'Remediation Playbook', margin);

  // Summary stats
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  txt(doc, GRAY);
  doc.text(`Total Actions: ${data.remediation_summary.total_actions}`, margin, y);
  y += 5;

  const byCat = data.remediation_summary.by_category;
  const catText = Object.entries(byCat).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`).join('  |  ');
  doc.text(`By Category: ${catText}`, margin, y);
  y += 10;

  // Top priority remediations
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Priority Remediation Actions', margin, y);
  y += 5;

  const remData = data.remediation_summary.top_priorities.map((r, idx) => [
    `P${idx + 1}`,
    r.title.length > 45 ? r.title.substring(0, 42) + '...' : r.title,
    (r.impact || '').toUpperCase(),
    r.effort || '',
    String(r.affected_identities),
    (r.compliance_refs || []).slice(0, 2).join(', '),
  ]);

  autoTable(doc, {
    startY: y,
    head: [['#', 'Remediation Action', 'Impact', 'Effort', 'Affected', 'Compliance']],
    body: remData,
    theme: 'striped',
    headStyles: { fillColor: BLUE, textColor: [255, 255, 255], fontSize: 8 },
    bodyStyles: { fontSize: 7 },
    columnStyles: {
      0: { cellWidth: 10, halign: 'center' },
      1: { cellWidth: 55 },
      2: { cellWidth: 18, halign: 'center' },
      3: { cellWidth: 18, halign: 'center' },
      4: { cellWidth: 18, halign: 'center' },
      5: { cellWidth: 40 },
    },
    margin: { left: margin, right: margin },
    didParseCell(hookData) {
      if (hookData.section === 'body' && hookData.column.index === 2) {
        const level = (hookData.cell.raw as string).toLowerCase();
        hookData.cell.styles.textColor = riskColor(level);
        hookData.cell.styles.fontStyle = 'bold';
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  // Quick wins section
  if (data.remediation_summary.quick_wins.length > 0) {
    // Check if we need a new page
    if (y > pageHeight - 60) {
      doc.addPage();
      y = addHeader(doc, 'Quick Wins (Low Effort)', margin);
    } else {
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      txt(doc, DARK);
      doc.text('Quick Wins (Low Effort)', margin, y);
      y += 5;
    }

    const qwData = data.remediation_summary.quick_wins.map(qw => [
      qw.title,
      (qw.impact || '').toUpperCase(),
      String(qw.affected_identities),
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Action', 'Impact', 'Affected Identities']],
      body: qwData,
      theme: 'striped',
      headStyles: { fillColor: GREEN, textColor: [255, 255, 255], fontSize: 8 },
      bodyStyles: { fontSize: 8 },
      margin: { left: margin, right: margin },
      tableWidth: contentWidth,
    });
  }

  addFooter(doc, 4);

  // ═══════════════════════════════════════════
  // LAST PAGE: Evidence & Methodology
  // ═══════════════════════════════════════════
  doc.addPage();
  y = addHeader(doc, 'Evidence & Methodology', margin);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  txt(doc, DARK);
  doc.text('This report was generated using data collected from the following Microsoft Azure and Entra ID APIs:', margin, y);
  y += 8;

  const sourceRows = Object.entries(data.evidence.sources).map(([key, value]) => [
    key.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase()),
    value,
  ]);

  autoTable(doc, {
    startY: y,
    head: [['Data Source', 'API Endpoint']],
    body: sourceRows,
    theme: 'striped',
    headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 8 },
    bodyStyles: { fontSize: 7 },
    margin: { left: margin, right: margin },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  doc.setFontSize(8);
  txt(doc, GRAY);
  doc.text('Methodology:', margin, y);
  y += 5;
  const methodLines = [
    '1. Identity Enumeration: Enumerate all identities (service principals, managed identities, users) via Microsoft Graph API.',
    '2. Role Analysis: Map Azure RBAC and Entra ID directory role assignments with privilege tier classification (T0-T3).',
    '3. Risk Scoring: Points-based risk calculation considering role criticality, credential health, activity status, and ownership.',
    '4. Remediation Matching: Pattern-match risk factors against the AuditGraph playbook library for actionable fix steps.',
    '5. Compliance Mapping: Map findings to SOC 2, HIPAA, PCI-DSS, and NIST 800-53 control requirements.',
  ];

  methodLines.forEach(line => {
    doc.text(line, margin, y, { maxWidth: contentWidth });
    y += 7;
  });

  y += 5;
  doc.setFontSize(7);
  doc.text('This report is generated by AuditGraph and should be reviewed by qualified security professionals.', margin, y);
  doc.text('The remediation recommendations are based on industry best practices and should be adapted to your organization\'s specific context.', margin, y + 4);

  addFooter(doc, doc.internal.pages.length - 1);

  // Save
  const dateStr = new Date().toISOString().split('T')[0];
  const safeName = (clientName || 'AuditGraph').replace(/[^a-zA-Z0-9]/g, '_');
  doc.save(`${safeName}_Security_Report_${dateStr}.pdf`);
}

// ─── Helpers ───────────────────────────────────────────────────────

function addHeader(doc: jsPDF, title: string, margin: number): number {
  const pageWidth = doc.internal.pageSize.getWidth();

  // Blue accent line
  fill(doc, BLUE);
  doc.rect(0, 0, pageWidth, 3, 'F');

  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text(title, margin, 20);

  // Thin separator
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(0.5);
  doc.line(margin, 24, pageWidth - margin, 24);

  return 32; // return Y position after header
}

function addFooter(doc: jsPDF, pageNum: number): void {
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  doc.setFontSize(7);
  txt(doc, GRAY);
  doc.text('AuditGraph Security Report', 20, pageHeight - 10);
  doc.text(`Page ${pageNum}`, pageWidth - 35, pageHeight - 10);
  doc.text('CONFIDENTIAL', pageWidth / 2, pageHeight - 10, { align: 'center' });
}


// ── Phase 82: Executive Posture Report (1-page landscape) ─────────

export function generateExecutiveReport(data: ReportData, clientName?: string): void {
  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth(); // 297
  const pageHeight = doc.internal.pageSize.getHeight(); // 210
  const margin = 15;

  // Compute posture score
  const total = data.stats.total_identities || 1;
  const crit = data.stats.critical || 0;
  const high = data.stats.high || 0;
  const critPct = (crit / total) * 100;
  const highPct = (high / total) * 100;
  const postureScore = Math.max(0, Math.round(100 - critPct * 3 - highPct * 1.5));

  const scoreColor: RGB = postureScore >= 80 ? GREEN : postureScore >= 60 ? [202, 138, 4] : RED;

  // Credential health
  const credTotal = (data.credential_health.expired + data.credential_health.expiring_soon + data.credential_health.healthy + data.credential_health.unknown) || 1;
  const credHealthPct = Math.round((data.credential_health.healthy / credTotal) * 100);

  // Days since last snapshot
  const daysSinceSnapshot = data.collected_at
    ? Math.max(0, Math.floor((Date.now() - new Date(data.collected_at).getTime()) / TIME_MS.DAY))
    : -1;

  // ── Header ──────────────────────────────────────────────────
  fill(doc, BLUE);
  doc.rect(0, 0, pageWidth, 20, 'F');
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(255, 255, 255);
  doc.text(clientName || 'Security Posture Report', margin, 13);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Generated: ${new Date().toLocaleDateString()}`, pageWidth - margin, 13, { align: 'right' });

  const topY = 30;

  // ── Left Column (40%): Posture Score Circle ─────────────────
  const leftWidth = (pageWidth - margin * 2) * 0.38;
  const circleCx = margin + leftWidth / 2;
  const circleCy = topY + 50;
  const circleR = 35;

  // Background circle
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(6);
  doc.circle(circleCx, circleCy, circleR);

  // Score arc (colored)
  doc.setDrawColor(scoreColor[0], scoreColor[1], scoreColor[2]);
  doc.setLineWidth(6);
  // Draw partial arc by overlaying — simplified to full circle with score text
  doc.circle(circleCx, circleCy, circleR);

  // Score number
  doc.setFontSize(36);
  doc.setFont('helvetica', 'bold');
  txt(doc, scoreColor);
  doc.text(`${postureScore}`, circleCx, circleCy + 5, { align: 'center' });

  // Score label
  doc.setFontSize(9);
  txt(doc, GRAY);
  doc.setFont('helvetica', 'normal');
  doc.text('POSTURE SCORE', circleCx, circleCy + 16, { align: 'center' });

  // Score description
  const scoreLabel = postureScore >= 80 ? 'Good' : postureScore >= 60 ? 'Needs Attention' : 'Critical';
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  txt(doc, scoreColor);
  doc.text(scoreLabel, circleCx, circleCy + 25, { align: 'center' });

  // Trend arrow
  if (data.previous_run) {
    const prevTotal = data.previous_run.total_identities || 1;
    const prevCritPct = ((data.previous_run.critical || 0) / prevTotal) * 100;
    const prevHighPct = ((data.previous_run.high || 0) / prevTotal) * 100;
    const prevScore = Math.max(0, Math.round(100 - prevCritPct * 3 - prevHighPct * 1.5));
    const delta = postureScore - prevScore;
    if (delta !== 0) {
      doc.setFontSize(8);
      txt(doc, delta > 0 ? GREEN : RED);
      doc.text(`${delta > 0 ? '+' : ''}${delta} from previous snapshot`, circleCx, circleCy + 33, { align: 'center' });
    }
  }

  // ── Right Column (60%): 2x3 Metric Grid ─────────────────────
  const rightX = margin + leftWidth + 10;
  const rightWidth = pageWidth - margin - rightX;
  const boxW = (rightWidth - 10) / 3;
  const boxH = 32;

  const ghostCount = (data.stats as Record<string, unknown>).ghost_count as number || 0;

  const metrics: { label: string; value: string; color: RGB }[] = [
    { label: 'Total Identities', value: `${data.stats.total_identities}`, color: DARK },
    { label: 'Critical / High Risk', value: `${crit + high}`, color: crit + high > 0 ? RED : GREEN },
    { label: 'Credential Health', value: `${credHealthPct}%`, color: credHealthPct >= 80 ? GREEN : credHealthPct >= 60 ? [202, 138, 4] : RED },
    { label: 'CA Coverage', value: data.conditional_access ? `${Math.round((data.conditional_access.covered / (data.conditional_access.total || 1)) * 100)}%` : 'N/A', color: BLUE },
    { label: 'Ghost Access', value: `${ghostCount}`, color: ghostCount > 0 ? RED : GREEN },
    { label: 'Days Since Snapshot', value: daysSinceSnapshot >= 0 ? `${daysSinceSnapshot}` : 'N/A', color: daysSinceSnapshot <= 1 ? GREEN : daysSinceSnapshot <= 7 ? [202, 138, 4] : RED },
  ];

  metrics.forEach((m, idx) => {
    const col = idx % 3;
    const row = Math.floor(idx / 3);
    const bx = rightX + col * (boxW + 5);
    const by = topY + row * (boxH + 8);

    // Box background
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(bx, by, boxW, boxH, 3, 3, 'F');

    // Value
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    txt(doc, m.color);
    doc.text(m.value, bx + boxW / 2, by + 15, { align: 'center' });

    // Label
    doc.setFontSize(7);
    doc.setFont('helvetica', 'normal');
    txt(doc, GRAY);
    doc.text(m.label, bx + boxW / 2, by + 24, { align: 'center' });
  });

  // ── Bottom Strip: Executive Summary ─────────────────────────
  const summaryY = topY + 90;
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, summaryY, pageWidth - margin * 2, 30, 3, 3, 'F');

  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('EXECUTIVE SUMMARY', margin + 6, summaryY + 8);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  txt(doc, GRAY);
  const summaryText = [
    `Your organization manages ${data.stats.total_identities} identities across cloud providers.`,
    crit > 0 ? `${crit} critical risk identities require immediate attention.` : 'No critical risk identities detected.',
    `Credential health is at ${credHealthPct}%. ${data.credential_health.expired > 0 ? data.credential_health.expired + ' credentials have expired.' : 'All credentials are current.'}`,
    ghostCount > 0 ? `WARNING: ${ghostCount} disabled/deleted identities still retain active role assignments (ghost access).` : '',
  ].filter(Boolean).join(' ');
  const splitSummary = doc.splitTextToSize(summaryText, pageWidth - margin * 2 - 12);
  doc.text(splitSummary, margin + 6, summaryY + 15);

  // ── Footer ──────────────────────────────────────────────────
  doc.setFontSize(7);
  txt(doc, GRAY);
  doc.text(`Generated by AuditGraph | Confidential | ${new Date().toLocaleDateString()}`, pageWidth / 2, pageHeight - 8, { align: 'center' });

  doc.save(`executive-posture-report-${new Date().toISOString().split('T')[0]}.pdf`);
}

/**
 * Generate a compliance-focused PDF report with framework mappings,
 * attack surface score breakdown, and risk driver summaries.
 */
export function generateComplianceReport(data: ReportData, attackSurface: any, clientName?: string): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 15;

  // ── Page 1: Cover ────────────────────────────────────────────
  fill(doc, [30, 58, 95]); // brand dark
  doc.rect(0, 0, pageWidth, 60, 'F');
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(255, 255, 255);
  doc.text('Identity Compliance Report', margin, 30);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(clientName || 'AuditGraph', margin, 42);
  doc.text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), margin, 50);

  let y = 72;

  // Attack Surface Score summary
  if (attackSurface) {
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    txt(doc, DARK);
    doc.text('Attack Surface Score', margin, y);
    y += 8;

    const score = attackSurface.score ?? 0;
    const grade = attackSurface.grade ?? '—';
    const scoreClr: RGB = score <= 20 ? GREEN : score <= 40 ? [37, 99, 235] : score <= 60 ? [202, 138, 4] : score <= 80 ? ORANGE : RED;

    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    txt(doc, scoreClr);
    doc.text(`${Math.round(score)} / 100`, margin, y + 8);

    doc.setFontSize(12);
    doc.text(`Grade: ${grade}`, margin + 50, y + 8);

    y += 20;

    // Pillar breakdown table
    const pillarRows = [
      ['Effective Privilege', `${attackSurface.pillars?.effective_privilege?.score?.toFixed(1) ?? '—'}`, '30%'],
      ['Credential Risk', `${attackSurface.pillars?.credential_risk?.score?.toFixed(1) ?? '—'}`, '20%'],
      ['Trust & Federation', `${attackSurface.pillars?.trust_federation?.score?.toFixed(1) ?? '—'}`, '20%'],
      ['Usage Dormancy', `${attackSurface.pillars?.usage_dormancy?.score?.toFixed(1) ?? '—'}`, '10%'],
      ['Ownership Governance', `${attackSurface.pillars?.ownership_governance?.score?.toFixed(1) ?? '—'}`, '10%'],
      ['External Exposure', `${attackSurface.pillars?.external_exposure?.score?.toFixed(1) ?? '—'}`, '10%'],
    ];

    autoTable(doc, {
      startY: y,
      head: [['Pillar', 'Score (0-100)', 'Weight']],
      body: pillarRows,
      theme: 'striped',
      headStyles: { fillColor: [30, 58, 95], fontSize: 9 },
      bodyStyles: { fontSize: 9 },
      margin: { left: margin, right: margin },
    });
    y = doc.lastAutoTable.finalY + 10;
  }

  // Risk summary section
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Risk Distribution', margin, y);
  y += 8;

  const riskRows = [
    ['Critical', String(data.stats.critical), `${((data.stats.critical / Math.max(data.stats.total_identities, 1)) * 100).toFixed(1)}%`],
    ['High', String(data.stats.high), `${((data.stats.high / Math.max(data.stats.total_identities, 1)) * 100).toFixed(1)}%`],
    ['Medium', String(data.stats.medium), `${((data.stats.medium / Math.max(data.stats.total_identities, 1)) * 100).toFixed(1)}%`],
    ['Low', String(data.stats.low), `${((data.stats.low / Math.max(data.stats.total_identities, 1)) * 100).toFixed(1)}%`],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Risk Level', 'Count', '% of Total']],
    body: riskRows,
    theme: 'striped',
    headStyles: { fillColor: [30, 58, 95], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: margin, right: margin },
  });
  y = doc.lastAutoTable.finalY + 10;

  // Compliance framework mapping
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Compliance Framework Mapping', margin, y);
  y += 8;

  const frameworkRows = [
    ['SOC2 CC6.1', 'Logical Access Controls', 'Identity privilege, MFA, credential rotation'],
    ['SOC2 CC6.3', 'Role-Based Access', 'Least privilege, dormant privileged identities'],
    ['CIS 1.1', 'Privileged Access', 'Global admin monitoring, T0/T1 surface'],
    ['CIS 1.4', 'Credential Management', 'Expiring/expired secret monitoring'],
    ['HIPAA 164.312(a)(1)', 'Access Control', 'Identity ownership, external access'],
    ['HIPAA 164.312(d)', 'Authentication', 'MFA enforcement, credential hygiene'],
    ['NIST AC-2', 'Account Management', 'Lifecycle, dormancy, ownership'],
    ['NIST AC-6', 'Least Privilege', 'Excessive privilege detection'],
    ['NIST IA-5', 'Authenticator Management', 'Secret rotation, credential health'],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Control', 'Domain', 'AuditGraph Coverage']],
    body: frameworkRows,
    theme: 'striped',
    headStyles: { fillColor: [30, 58, 95], fontSize: 8 },
    bodyStyles: { fontSize: 8 },
    margin: { left: margin, right: margin },
    columnStyles: { 2: { cellWidth: 65 } },
  });
  y = doc.lastAutoTable.finalY + 10;

  // Credential health
  if (y > 230) { doc.addPage(); y = 20; }

  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Credential Health', margin, y);
  y += 8;

  const ch = data.credential_health;
  const credRows = [
    ['Expired', String(ch.expired), ch.expired > 0 ? 'ACTION REQUIRED' : 'OK'],
    ['Expiring Soon (<30d)', String(ch.expiring_soon), ch.expiring_soon > 0 ? 'MONITOR' : 'OK'],
    ['Healthy', String(ch.healthy), 'OK'],
    ['No Credentials', String(ch.unknown), 'N/A'],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Status', 'Count', 'Action']],
    body: credRows,
    theme: 'striped',
    headStyles: { fillColor: [30, 58, 95], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: margin, right: margin },
  });
  y = doc.lastAutoTable.finalY + 10;

  // Top risks
  if (data.top_risks && data.top_risks.length > 0) {
    if (y > 200) { doc.addPage(); y = 20; }

    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    txt(doc, DARK);
    doc.text('Top Risk Identities', margin, y);
    y += 8;

    const topRows = data.top_risks.slice(0, 10).map(r => [
      r.display_name || r.identity_id || '',
      (r.risk_level || 'unknown').toUpperCase(),
      String(r.risk_score || 0),
      r.identity_category || '',
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Identity', 'Risk Level', 'Score', 'Category']],
      body: topRows,
      theme: 'striped',
      headStyles: { fillColor: [30, 58, 95], fontSize: 8 },
      bodyStyles: { fontSize: 8 },
      margin: { left: margin, right: margin },
    });
  }

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    txt(doc, GRAY);
    doc.text(
      `AuditGraph Compliance Report | Confidential | Page ${i} of ${totalPages} | ${new Date().toLocaleDateString()}`,
      pageWidth / 2, doc.internal.pageSize.getHeight() - 8, { align: 'center' }
    );
  }

  doc.save(`compliance-report-${new Date().toISOString().split('T')[0]}.pdf`);
}
