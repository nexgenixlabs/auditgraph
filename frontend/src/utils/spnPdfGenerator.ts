/**
 * AuditGraph SPN Exposure Intelligence PDF Report
 *
 * Generates an exposure-focused workload identity security audit report
 * using jsPDF + autotable. Uses 5-component exposure scoring (0-100),
 * findings, and activity inference data.
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

// ─── Types ────────────────────────────────────────────────────────

interface SPNRow {
  display_name: string;
  identity_category: string;
  identity_type?: string;
  risk_level: string;
  risk_score: number;
  blast_radius: string;
  critical_roles: string[];
  credential_risk: string;
  credential_count: number;
  next_expiry: string | null;
  activity_status: string;
  role_count: number;
  rbac_role_count: number;
  entra_role_count: number;
  owner_display_name: string | null;
  identity_id: string;
  exposure_score?: number;
  privilege_score?: number;
  credential_risk_score?: number;
  lifecycle_state?: string;
  owner_status?: string;
  effective_scope_flag?: string;
  can_escalate?: boolean;
}

interface SPNStats {
  total: number;
  custom: number;
  microsoft: number;
  critical: number;
  high_risk: number;
  expired_credentials: number;
  expiring_soon: number;
  no_credentials: number;
  by_blast_radius: Record<string, number>;
  by_activity: Record<string, number>;
  exposure_critical?: number;
  can_escalate_count?: number;
  orphaned_privileged?: number;
  blind_count?: number;
  cross_sub_count?: number;
  avg_exposure_score?: number;
  by_type?: { spn?: number; managed_identity?: number; app_registration?: number };
}

interface ExposureFinding {
  finding_type: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
  component: string;
  score_impact: number;
}

interface SPNDetail {
  identity: Record<string, unknown>;
  roles: Array<Record<string, unknown>>;
  entra_roles: Array<Record<string, unknown>>;
  credentials: Array<Record<string, unknown>>;
  blast_radius: string;
  critical_roles: string[];
  risk_summary: string[];
  recommendations: Array<{ priority: string; action: string; reason: string }>;
  attacker_narrative: string[];
  auditor_questions: string[];
  exposure?: {
    total: number;
    privilege: number;
    credential_risk: number;
    exposure: number;
    lifecycle: number;
    visibility: number;
    can_escalate: boolean;
    effective_scope_flag: string;
    lifecycle_state: string;
    owner_status: string;
    credential_age_days: number;
    critical_overrides: Array<{ type: string; description: string }>;
  };
  findings?: ExposureFinding[];
  activity_inference?: { confidence: number; classification: string };
}

// ─── Colors ───────────────────────────────────────────────────────

type RGB = [number, number, number];
const BRAND: RGB = [37, 99, 235];
const DARK: RGB = [17, 24, 39];
const GRAY: RGB = [107, 114, 128];
const RED: RGB = [220, 38, 38];
const ORANGE: RGB = [234, 88, 12];
const GREEN: RGB = [22, 163, 74];
const PURPLE: RGB = [124, 58, 237];

function exposureColor(score: number): RGB {
  if (score >= 80) return RED;
  if (score >= 60) return ORANGE;
  if (score >= 35) return [202, 138, 4];
  return GREEN;
}

function severityColor(level: string): RGB {
  switch (level?.toLowerCase()) {
    case 'critical': return RED;
    case 'high': return ORANGE;
    case 'medium': return [202, 138, 4];
    case 'low': return GREEN;
    default: return GRAY;
  }
}

function fill(doc: jsPDF, c: RGB) { doc.setFillColor(c[0], c[1], c[2]); }
function txt(doc: jsPDF, c: RGB) { doc.setTextColor(c[0], c[1], c[2]); }

// ─── Helpers ──────────────────────────────────────────────────────

function addHeader(doc: jsPDF, title: string, margin: number): number {
  const pageWidth = doc.internal.pageSize.getWidth();
  fill(doc, PURPLE);
  doc.rect(0, 0, pageWidth, 3, 'F');
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text(title, margin, 20);
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(0.5);
  doc.line(margin, 24, pageWidth - margin, 24);
  return 32;
}

function addFooter(doc: jsPDF, pageNum: number): void {
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  doc.setFontSize(7);
  txt(doc, GRAY);
  doc.text('AuditGraph Exposure Intelligence Report', 20, pageHeight - 10);
  doc.text(`Page ${pageNum}`, pageWidth - 35, pageHeight - 10);
  doc.text('CONFIDENTIAL', pageWidth / 2, pageHeight - 10, { align: 'center' });
}

function categoryLabel(cat: string): string {
  if (cat === 'service_principal') return 'SPN';
  if (cat === 'managed_identity_user') return 'MI (User)';
  if (cat === 'managed_identity_system') return 'MI (System)';
  if (cat === 'app_registration') return 'App Reg';
  return cat;
}

function daysUntilStr(iso: string | null): string {
  if (!iso) return 'N/A';
  const d = Math.ceil((new Date(iso).getTime() - Date.now()) / TIME_MS.DAY);
  if (d < 0) return `${Math.abs(d)}d ago`;
  if (d === 0) return 'Today';
  return `${d}d`;
}

function exposureLabel(score: number): string {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

// ─── Main Export ──────────────────────────────────────────────────

export function generateSPNReport(
  spns: SPNRow[],
  stats: SPNStats,
  criticalDetails: SPNDetail[],
  clientName?: string
): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;
  let pageNum = 1;

  // ═══════════════════════════════════════════
  // PAGE 1: Cover
  // ═══════════════════════════════════════════
  fill(doc, PURPLE);
  doc.rect(0, 0, pageWidth, 80, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('AuditGraph', margin, 35);

  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text('Workload Identity Exposure Report', margin, 48);

  doc.setFontSize(9);
  doc.text('Attack-based exposure scoring for non-human identities', margin, 58);

  // Client info
  txt(doc, DARK);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(clientName || 'Exposure Intelligence Report', margin, 105);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  txt(doc, GRAY);
  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });
  doc.text(`Generated: ${reportDate}`, margin, 115);
  doc.text(`Total Workload Identities: ${stats.total} (${stats.custom} custom, ${stats.microsoft} Microsoft)`, margin, 122);

  // Type breakdown
  if (stats.by_type) {
    const bt = stats.by_type;
    doc.text(
      `SPNs: ${bt.spn ?? 0}  |  App Registrations: ${bt.app_registration ?? 0}  |  Managed Identities: ${bt.managed_identity ?? 0}`,
      margin, 129
    );
  }

  // Key findings — exposure-focused
  const findingsY = 140;
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Exposure Summary', margin, findingsY);

  const findings = [
    ['Critical Exposure (\u226580)', String(stats.exposure_critical ?? 0)],
    ['Can Escalate Privileges', String(stats.can_escalate_count ?? 0)],
    ['Orphaned & Privileged', String(stats.orphaned_privileged ?? 0)],
    ['Visibility Gap (No Telemetry)', String(stats.blind_count ?? 0)],
    ['Cross-Subscription Access', String(stats.cross_sub_count ?? 0)],
    ['Average Exposure Score', String(stats.avg_exposure_score ?? 0)],
    ['Expired Credentials', String(stats.expired_credentials)],
    ['Expiring < 30d', String(stats.expiring_soon)],
  ];

  autoTable(doc, {
    startY: findingsY + 5,
    head: [['Metric', 'Count']],
    body: findings,
    theme: 'grid',
    headStyles: { fillColor: PURPLE, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9, textColor: DARK },
    columnStyles: { 0: { cellWidth: 65 }, 1: { cellWidth: 30, halign: 'center' } },
    margin: { left: margin, right: margin },
    tableWidth: 105,
    didParseCell(hookData) {
      if (hookData.section === 'body' && hookData.column.index === 1) {
        const val = parseInt(hookData.cell.raw as string, 10);
        if (val > 0 && hookData.row.index < 5) {
          hookData.cell.styles.textColor = RED;
          hookData.cell.styles.fontStyle = 'bold';
        }
      }
    },
  });

  addFooter(doc, pageNum);

  // ═══════════════════════════════════════════
  // PAGE 2: Executive Summary
  // ═══════════════════════════════════════════
  doc.addPage();
  pageNum++;
  let y = addHeader(doc, 'Exposure Assessment', margin);

  // Exposure score distribution
  const expCritical = stats.exposure_critical ?? 0;
  const customTotal = stats.custom || 1;
  const postureScore = Math.round(((customTotal - expCritical) / customTotal) * 100);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Exposure Posture', margin, y);
  y += 8;

  // Score bar
  doc.setFillColor(229, 231, 235);
  doc.roundedRect(margin, y, contentWidth, 8, 2, 2, 'F');
  const scoreColor = postureScore >= 70 ? GREEN : postureScore >= 40 ? ORANGE : RED;
  fill(doc, scoreColor);
  doc.roundedRect(margin, y, contentWidth * (postureScore / 100), 8, 2, 2, 'F');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text(`${postureScore}% secure`, margin + 4, y + 5.5);
  y += 16;

  // Component breakdown for fleet average
  txt(doc, DARK);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Scoring Components (0-100 scale)', margin, y);
  y += 5;

  const componentRows = [
    ['Privilege', '40', 'Tenant-admin roles, subscription Owner/Contributor, high-risk API permissions, PIM eligible'],
    ['Credential Risk', '25', 'Expired credentials, aged secrets, multiple active secrets, no certificate auth'],
    ['Exposure', '20', 'Cross-subscription access, management group scope, multi-tenant apps, broad RG access'],
    ['Lifecycle', '10', 'Orphaned SPNs, dormant identities, aging without credential rotation'],
    ['Visibility', '5', 'No sign-in telemetry, no Conditional Access coverage'],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Component', 'Max', 'Key Factors']],
    body: componentRows,
    theme: 'striped',
    headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 8 },
    columnStyles: { 0: { cellWidth: 28, fontStyle: 'bold' }, 1: { cellWidth: 12, halign: 'center' }, 2: { cellWidth: contentWidth - 40 } },
    margin: { left: margin, right: margin },
    tableWidth: contentWidth,
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  // Activity breakdown
  if (y < pageHeight - 60) {
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    txt(doc, DARK);
    doc.text('Activity Status', margin, y);
    y += 5;

    const actRows = Object.entries(stats.by_activity || {}).map(([status, count]) => [
      status.replace(/_/g, ' '),
      String(count),
      `${Math.round((count / customTotal) * 100)}%`,
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Status', 'Count', '% of Custom']],
      body: actRows,
      theme: 'striped',
      headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 9 },
      bodyStyles: { fontSize: 9 },
      margin: { left: margin, right: margin },
      tableWidth: 120,
    });
  }

  addFooter(doc, pageNum);

  // ═══════════════════════════════════════════
  // PAGE 3: Full SPN Inventory
  // ═══════════════════════════════════════════
  doc.addPage();
  pageNum++;
  y = addHeader(doc, 'Workload Identity Inventory', margin);

  const inventoryData = spns.map(s => [
    s.display_name.length > 22 ? s.display_name.substring(0, 19) + '...' : s.display_name,
    categoryLabel(s.identity_category),
    String(s.exposure_score ?? 0),
    exposureLabel(s.exposure_score ?? 0),
    String(s.privilege_score ?? 0),
    String(s.credential_risk_score ?? 0),
    (s.lifecycle_state || 'blind').replace('_', ' '),
    (s.owner_status || 'unknown').replace('_', ' '),
    s.can_escalate ? 'YES' : '',
    s.owner_display_name || 'None',
  ]);

  autoTable(doc, {
    startY: y,
    head: [['Name', 'Type', 'Score', 'Level', 'Priv', 'Cred', 'Lifecycle', 'Owner', 'Esc', 'Owner Name']],
    body: inventoryData,
    theme: 'striped',
    headStyles: { fillColor: PURPLE, textColor: [255, 255, 255], fontSize: 6.5 },
    bodyStyles: { fontSize: 6 },
    columnStyles: {
      0: { cellWidth: 22 },
      1: { cellWidth: 12 },
      2: { cellWidth: 10, halign: 'center' },
      3: { cellWidth: 14, halign: 'center' },
      4: { cellWidth: 10, halign: 'center' },
      5: { cellWidth: 10, halign: 'center' },
      6: { cellWidth: 18 },
      7: { cellWidth: 16 },
      8: { cellWidth: 8, halign: 'center' },
      9: { cellWidth: 20 },
    },
    margin: { left: margin, right: margin },
    didParseCell(hookData) {
      if (hookData.section === 'body') {
        if (hookData.column.index === 3) {
          const lvl = (hookData.cell.raw as string).toLowerCase();
          hookData.cell.styles.textColor = severityColor(lvl);
          hookData.cell.styles.fontStyle = 'bold';
        }
        if (hookData.column.index === 8 && hookData.cell.raw === 'YES') {
          hookData.cell.styles.textColor = RED;
          hookData.cell.styles.fontStyle = 'bold';
        }
      }
    },
    didDrawPage() {
      addFooter(doc, pageNum);
    },
  });

  // ═══════════════════════════════════════════
  // PER-SPN DETAIL PAGES (top 10 by exposure)
  // ═══════════════════════════════════════════
  for (const spnDetail of criticalDetails) {
    const identity = spnDetail.identity;
    const spnName = (identity.display_name as string) || 'Unknown';
    const exp = spnDetail.exposure;

    doc.addPage();
    pageNum++;

    // Header
    fill(doc, PURPLE);
    doc.rect(0, 0, pageWidth, 3, 'F');

    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    txt(doc, DARK);
    const truncName = spnName.length > 50 ? spnName.substring(0, 47) + '...' : spnName;
    doc.text(truncName, margin, 18);

    doc.setFontSize(8);
    txt(doc, GRAY);
    const expScore = exp?.total ?? 0;
    doc.text(
      `${categoryLabel(identity.identity_category as string)}  |  Exposure: ${expScore}/100 (${exposureLabel(expScore)})  |  Lifecycle: ${(exp?.lifecycle_state || 'blind').replace('_', ' ')}`,
      margin, 25
    );

    doc.setDrawColor(229, 231, 235);
    doc.setLineWidth(0.5);
    doc.line(margin, 28, pageWidth - margin, 28);
    y = 35;

    // Component breakdown table
    if (exp) {
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, DARK);
      doc.text('EXPOSURE COMPONENTS', margin, y);
      y += 3;

      autoTable(doc, {
        startY: y,
        head: [['Component', 'Score', 'Max']],
        body: [
          ['Privilege', String(exp.privilege), '40'],
          ['Credential Risk', String(exp.credential_risk), '25'],
          ['Exposure', String(exp.exposure), '20'],
          ['Lifecycle', String(exp.lifecycle), '10'],
          ['Visibility', String(exp.visibility), '5'],
          ['TOTAL', String(exp.total), '100'],
        ],
        theme: 'striped',
        headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 8 },
        bodyStyles: { fontSize: 7 },
        columnStyles: { 0: { fontStyle: 'bold' }, 1: { halign: 'center' }, 2: { halign: 'center' } },
        margin: { left: margin, right: margin },
        tableWidth: 80,
        didParseCell(hookData) {
          if (hookData.section === 'body' && hookData.row.index === 5) {
            hookData.cell.styles.fontStyle = 'bold';
            const total = parseInt(hookData.cell.raw as string, 10);
            if (hookData.column.index === 1) {
              hookData.cell.styles.textColor = exposureColor(total || exp.total);
            }
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 5;

      // Activity inference
      if (spnDetail.activity_inference) {
        doc.setFontSize(8);
        txt(doc, GRAY);
        doc.text(
          `Activity Inference: ${spnDetail.activity_inference.confidence}% confidence \u2014 ${(spnDetail.activity_inference.classification || 'blind').replace('_', ' ')}`,
          margin, y
        );
        y += 6;
      }
    }

    // Findings
    if (spnDetail.findings && spnDetail.findings.length > 0) {
      if (y > pageHeight - 50) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, RED);
      doc.text(`FINDINGS (${spnDetail.findings.length})`, margin, y);
      y += 3;

      const findingsData = spnDetail.findings.slice(0, 10).map(f => [
        f.severity.toUpperCase(),
        f.title,
        f.remediation.substring(0, 55),
        `+${f.score_impact}`,
      ]);

      autoTable(doc, {
        startY: y,
        head: [['Severity', 'Finding', 'Remediation', 'Impact']],
        body: findingsData,
        theme: 'striped',
        headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 7.5 },
        bodyStyles: { fontSize: 7 },
        columnStyles: {
          0: { cellWidth: 16, halign: 'center' },
          1: { cellWidth: 50 },
          2: { cellWidth: contentWidth - 80 },
          3: { cellWidth: 14, halign: 'center' },
        },
        margin: { left: margin, right: margin },
        didParseCell(hookData) {
          if (hookData.section === 'body' && hookData.column.index === 0) {
            hookData.cell.styles.textColor = severityColor((hookData.cell.raw as string).toLowerCase());
            hookData.cell.styles.fontStyle = 'bold';
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 5;
    }

    // Risk Summary (legacy, still useful)
    if (spnDetail.risk_summary.length > 0) {
      if (y > pageHeight - 50) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, RED);
      doc.text('RISK SUMMARY', margin, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      txt(doc, DARK);
      for (const point of spnDetail.risk_summary) {
        const wrapped = doc.splitTextToSize(`  \u2022  ${point}`, contentWidth);
        doc.text(wrapped, margin, y);
        y += wrapped.length * 4;
      }
      y += 3;
    }

    // Recommendations
    if (spnDetail.recommendations.length > 0) {
      if (y > pageHeight - 40) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, DARK);
      doc.text('RECOMMENDATIONS', margin, y);
      y += 3;

      autoTable(doc, {
        startY: y,
        head: [['Priority', 'Action', 'Reason']],
        body: spnDetail.recommendations.map(r => [
          r.priority.toUpperCase(),
          r.action,
          r.reason.substring(0, 60),
        ]),
        theme: 'striped',
        headStyles: { fillColor: PURPLE, textColor: [255, 255, 255], fontSize: 8 },
        bodyStyles: { fontSize: 7 },
        columnStyles: {
          0: { cellWidth: 18, halign: 'center' },
          1: { cellWidth: 60 },
          2: { cellWidth: contentWidth - 78 },
        },
        margin: { left: margin, right: margin },
        didParseCell(hookData) {
          if (hookData.section === 'body' && hookData.column.index === 0) {
            hookData.cell.styles.textColor = severityColor((hookData.cell.raw as string).toLowerCase());
            hookData.cell.styles.fontStyle = 'bold';
          }
        },
      });
    }

    addFooter(doc, pageNum);
  }

  // ═══════════════════════════════════════════
  // LAST PAGE: Methodology
  // ═══════════════════════════════════════════
  doc.addPage();
  pageNum++;
  y = addHeader(doc, 'Methodology & Scope', margin);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  txt(doc, DARK);
  doc.text('This report uses attack-based exposure scoring (0-100) across 5 weighted components:', margin, y);
  y += 8;

  const methodLines = [
    '1. Privilege (max 40): Entra directory roles, Azure RBAC roles, Graph API permissions, PIM eligibility.',
    '2. Credential Risk (max 25): Expired credentials, secret age, multiple active secrets, certificate usage.',
    '3. Exposure (max 20): Cross-subscription access, management group scope, multi-tenant apps, broad RG access.',
    '4. Lifecycle (max 10): Orphaned identities, dormancy detection, creation age without rotation.',
    '5. Visibility (max 5): Sign-in telemetry gaps, Conditional Access coverage.',
    '',
    'Activity Inference: P2-independent confidence score (0-100%) using credential modification dates,',
    '  role assignment changes, sign-in data, and PIM activations. Classifies identities as Active,',
    '  Possibly Active, Likely Dormant, or Visibility Gap (blind) — framed as exposure finding, not limitation.',
    '',
    'Critical Overrides force score to 100/100 for combinations like: tenant-admin + expired credentials,',
    '  orphaned + subscription Owner, cross-subscription + no audit logging, can-escalate + blind lifecycle.',
  ];

  doc.setFontSize(8);
  methodLines.forEach(line => {
    const wrapped = doc.splitTextToSize(line, contentWidth);
    doc.text(wrapped, margin, y);
    y += wrapped.length * 4.5;
  });

  y += 8;
  doc.setFontSize(7);
  txt(doc, GRAY);
  doc.text('This report is generated by AuditGraph and should be reviewed by qualified security professionals.', margin, y);
  doc.text('Recommendations should be adapted to your organization\'s specific security policies and risk appetite.', margin, y + 4);

  addFooter(doc, pageNum);

  // Save
  const dateStr = new Date().toISOString().split('T')[0];
  const safeName = (clientName || 'AuditGraph').replace(/[^a-zA-Z0-9]/g, '_');
  doc.save(`${safeName}_Exposure_Intelligence_Report_${dateStr}.pdf`);
}

// Backward compat alias
export { generateSPNReport as generateWorkloadReport };
