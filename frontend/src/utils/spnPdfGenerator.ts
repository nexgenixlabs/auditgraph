/**
 * AuditGraph SPN Privilege Report PDF Generator
 *
 * Generates a focused service principal security audit report
 * using jsPDF + autotable. Called from SPNDashboard with data
 * fetched from /api/spns and /api/spns/stats.
 */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

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

function riskColor(level: string): RGB {
  switch (level?.toLowerCase()) {
    case 'critical': return RED;
    case 'high': return ORANGE;
    case 'medium': return [202, 138, 4];
    case 'low': return GREEN;
    default: return GRAY;
  }
}

function blastColor(level: string): RGB {
  switch (level?.toLowerCase()) {
    case 'high': return RED;
    case 'medium': return ORANGE;
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
  doc.text('AuditGraph SPN Privilege Report', 20, pageHeight - 10);
  doc.text(`Page ${pageNum}`, pageWidth - 35, pageHeight - 10);
  doc.text('CONFIDENTIAL', pageWidth / 2, pageHeight - 10, { align: 'center' });
}

function categoryLabel(cat: string): string {
  if (cat === 'service_principal') return 'SPN';
  if (cat === 'managed_identity_user') return 'MI (User)';
  if (cat === 'managed_identity_system') return 'MI (System)';
  return cat;
}

function daysUntilStr(iso: string | null): string {
  if (!iso) return 'N/A';
  const d = Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
  if (d < 0) return `${Math.abs(d)}d ago`;
  if (d === 0) return 'Today';
  return `${d}d`;
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
  doc.text('Service Principal Privilege Report', margin, 48);

  doc.setFontSize(9);
  doc.text('Non-human identity security assessment', margin, 58);

  // Client info
  txt(doc, DARK);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(clientName || 'SPN Privilege Report', margin, 105);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  txt(doc, GRAY);
  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });
  doc.text(`Generated: ${reportDate}`, margin, 115);
  doc.text(`Total Service Principals: ${stats.total} (${stats.custom} custom, ${stats.microsoft} Microsoft)`, margin, 122);

  // Key findings on cover
  const findingsY = 140;
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('Key Findings', margin, findingsY);

  const findings = [
    ['Critical Risk SPNs', String(stats.critical)],
    ['High Risk SPNs', String(stats.high_risk)],
    ['Expired Credentials', String(stats.expired_credentials)],
    ['Credentials Expiring < 30d', String(stats.expiring_soon)],
    ['No Credentials', String(stats.no_credentials)],
    ['High Blast Radius', String(stats.by_blast_radius?.high || 0)],
    ['Medium Blast Radius', String(stats.by_blast_radius?.medium || 0)],
  ];

  autoTable(doc, {
    startY: findingsY + 5,
    head: [['Metric', 'Count']],
    body: findings,
    theme: 'grid',
    headStyles: { fillColor: PURPLE, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9, textColor: DARK },
    columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 30, halign: 'center' } },
    margin: { left: margin, right: margin },
    tableWidth: 100,
    didParseCell(hookData) {
      if (hookData.section === 'body' && hookData.column.index === 1) {
        const val = parseInt(hookData.cell.raw as string, 10);
        if (val > 0 && hookData.row.index < 3) {
          hookData.cell.styles.textColor = RED;
          hookData.cell.styles.fontStyle = 'bold';
        }
      }
    },
  });

  // Blast radius distribution
  const brY = (doc as any).lastAutoTable.finalY + 10;
  doc.setFontSize(9);
  txt(doc, GRAY);
  const br = stats.by_blast_radius || {};
  doc.text(`Blast Radius Distribution: High=${br.high || 0}  Medium=${br.medium || 0}  Low=${br.low || 0}  None=${br.none || 0}`, margin, brY);

  addFooter(doc, pageNum);

  // ═══════════════════════════════════════════
  // PAGE 2: Executive Summary
  // ═══════════════════════════════════════════
  doc.addPage();
  pageNum++;
  let y = addHeader(doc, 'Executive Summary', margin);

  // Posture score for SPNs
  const critHighCount = stats.critical + stats.high_risk;
  const customTotal = stats.custom || 1;
  const posture = Math.round(((customTotal - critHighCount) / customTotal) * 100);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  txt(doc, DARK);
  doc.text('SPN Security Posture', margin, y);
  y += 8;

  // Score bar
  doc.setFillColor(229, 231, 235);
  doc.roundedRect(margin, y, contentWidth, 8, 2, 2, 'F');
  const scoreColor = posture >= 70 ? GREEN : posture >= 40 ? ORANGE : RED;
  fill(doc, scoreColor);
  doc.roundedRect(margin, y, contentWidth * (posture / 100), 8, 2, 2, 'F');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text(`${posture}%`, margin + 4, y + 5.5);
  y += 16;

  // Credential health summary
  txt(doc, DARK);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Credential Health', margin, y);
  y += 5;

  const credRows = [
    ['Expired', String(stats.expired_credentials), stats.expired_credentials > 0 ? 'ACTION NEEDED' : 'OK'],
    ['Expiring < 30d', String(stats.expiring_soon), stats.expiring_soon > 0 ? 'MONITOR' : 'OK'],
    ['No Credentials', String(stats.no_credentials), stats.no_credentials > 0 ? 'VERIFY' : 'OK'],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Status', 'Count', 'Action']],
    body: credRows,
    theme: 'striped',
    headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 9 },
    bodyStyles: { fontSize: 9 },
    margin: { left: margin, right: margin },
    tableWidth: 130,
    didParseCell(hookData) {
      if (hookData.section === 'body' && hookData.column.index === 2) {
        const action = hookData.cell.raw as string;
        if (action === 'ACTION NEEDED') hookData.cell.styles.textColor = RED;
        else if (action === 'MONITOR') hookData.cell.styles.textColor = ORANGE;
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  // Activity breakdown
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

  addFooter(doc, pageNum);

  // ═══════════════════════════════════════════
  // PAGE 3: Full SPN Inventory
  // ═══════════════════════════════════════════
  doc.addPage();
  pageNum++;
  y = addHeader(doc, 'SPN Inventory', margin);

  const inventoryData = spns.map(s => [
    s.display_name.length > 25 ? s.display_name.substring(0, 22) + '...' : s.display_name,
    categoryLabel(s.identity_category),
    (s.risk_level || '').toUpperCase(),
    String(s.risk_score),
    (s.blast_radius || 'none').toUpperCase(),
    (s.critical_roles || []).slice(0, 2).join(', ') || '—',
    (s.credential_risk || 'unknown').replace('_', ' '),
    daysUntilStr(s.next_expiry),
    (s.activity_status || 'unknown').replace('_', ' '),
    `${s.rbac_role_count}R ${s.entra_role_count}E`,
    s.owner_display_name || 'None',
  ]);

  autoTable(doc, {
    startY: y,
    head: [['Name', 'Type', 'Risk', 'Score', 'Blast', 'Critical Roles', 'Cred Risk', 'Expiry', 'Activity', 'Roles', 'Owner']],
    body: inventoryData,
    theme: 'striped',
    headStyles: { fillColor: PURPLE, textColor: [255, 255, 255], fontSize: 6.5 },
    bodyStyles: { fontSize: 6 },
    columnStyles: {
      0: { cellWidth: 24 },
      1: { cellWidth: 13 },
      2: { cellWidth: 11, halign: 'center' },
      3: { cellWidth: 9, halign: 'center' },
      4: { cellWidth: 11, halign: 'center' },
      5: { cellWidth: 25 },
      6: { cellWidth: 16 },
      7: { cellWidth: 14, halign: 'center' },
      8: { cellWidth: 16 },
      9: { cellWidth: 13, halign: 'center' },
      10: { cellWidth: 18 },
    },
    margin: { left: margin, right: margin },
    didParseCell(hookData) {
      if (hookData.section === 'body') {
        if (hookData.column.index === 2) {
          hookData.cell.styles.textColor = riskColor((hookData.cell.raw as string).toLowerCase());
          hookData.cell.styles.fontStyle = 'bold';
        }
        if (hookData.column.index === 4) {
          hookData.cell.styles.textColor = blastColor((hookData.cell.raw as string).toLowerCase());
          hookData.cell.styles.fontStyle = 'bold';
        }
      }
    },
    didDrawPage() {
      addFooter(doc, pageNum);
    },
  });

  // ═══════════════════════════════════════════
  // PER-CRITICAL-SPN DETAIL PAGES
  // ═══════════════════════════════════════════
  for (const spnDetail of criticalDetails) {
    const identity = spnDetail.identity;
    const spnName = (identity.display_name as string) || 'Unknown';

    doc.addPage();
    pageNum++;

    // Detail header with risk + blast badges
    fill(doc, PURPLE);
    doc.rect(0, 0, pageWidth, 3, 'F');

    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    txt(doc, DARK);
    const truncName = spnName.length > 50 ? spnName.substring(0, 47) + '...' : spnName;
    doc.text(truncName, margin, 18);

    doc.setFontSize(8);
    txt(doc, GRAY);
    doc.text(`${categoryLabel(identity.identity_category as string)}  |  Risk: ${((identity.risk_level as string) || '').toUpperCase()}  |  Blast Radius: ${(spnDetail.blast_radius || 'none').toUpperCase()}`, margin, 25);

    doc.setDrawColor(229, 231, 235);
    doc.setLineWidth(0.5);
    doc.line(margin, 28, pageWidth - margin, 28);
    y = 35;

    // Risk Summary
    if (spnDetail.risk_summary.length > 0) {
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

    // Attacker Narrative
    if (spnDetail.attacker_narrative.length > 0) {
      if (y > pageHeight - 50) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, [127, 29, 29]); // red-900
      doc.text('WHAT AN ATTACKER COULD DO', margin, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      txt(doc, DARK);
      for (const point of spnDetail.attacker_narrative) {
        const wrapped = doc.splitTextToSize(`  \u25B8  ${point}`, contentWidth);
        doc.text(wrapped, margin, y);
        y += wrapped.length * 4;
      }
      y += 3;
    }

    // Auditor Questions
    if (spnDetail.auditor_questions.length > 0) {
      if (y > pageHeight - 50) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, BRAND);
      doc.text('WHAT AUDITORS WILL QUESTION', margin, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      txt(doc, DARK);
      for (const q of spnDetail.auditor_questions) {
        const wrapped = doc.splitTextToSize(`  ?  ${q}`, contentWidth);
        doc.text(wrapped, margin, y);
        y += wrapped.length * 4;
      }
      y += 3;
    }

    // Credentials table
    if (spnDetail.credentials.length > 0) {
      if (y > pageHeight - 50) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, DARK);
      doc.text(`CREDENTIALS (${spnDetail.credentials.length})`, margin, y);
      y += 3;

      const credData = spnDetail.credentials.map(c => {
        const endDate = c.end_datetime as string | null;
        const isExpired = endDate ? new Date(endDate) < new Date() : false;
        return [
          (c.credential_type as string) || '?',
          (c.display_name as string)?.substring(0, 25) || '—',
          endDate ? new Date(endDate).toLocaleDateString() : 'N/A',
          isExpired ? 'EXPIRED' : daysUntilStr(endDate),
        ];
      });

      autoTable(doc, {
        startY: y,
        head: [['Type', 'Name', 'Expiry Date', 'Status']],
        body: credData,
        theme: 'striped',
        headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 8 },
        bodyStyles: { fontSize: 7 },
        margin: { left: margin, right: margin },
        tableWidth: contentWidth,
        didParseCell(hookData) {
          if (hookData.section === 'body' && hookData.column.index === 3) {
            const val = hookData.cell.raw as string;
            if (val === 'EXPIRED') {
              hookData.cell.styles.textColor = RED;
              hookData.cell.styles.fontStyle = 'bold';
            }
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 5;
    }

    // Roles table
    const allRoles = [
      ...spnDetail.roles.map(r => ({ name: r.role_name as string, type: 'RBAC', scope: r.scope as string })),
      ...spnDetail.entra_roles.map(r => ({ name: r.role_name as string, type: 'Entra', scope: 'Directory' })),
    ];
    if (allRoles.length > 0) {
      if (y > pageHeight - 40) { doc.addPage(); pageNum++; y = addHeader(doc, `${truncName} (cont.)`, margin); }
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      txt(doc, DARK);
      doc.text(`ROLES (${allRoles.length})`, margin, y);
      y += 3;

      autoTable(doc, {
        startY: y,
        head: [['Role', 'Type', 'Scope']],
        body: allRoles.map(r => [
          r.name?.substring(0, 35) || '—',
          r.type,
          (r.scope || '—').length > 50 ? (r.scope || '').substring(0, 47) + '...' : (r.scope || '—'),
        ]),
        theme: 'striped',
        headStyles: { fillColor: DARK, textColor: [255, 255, 255], fontSize: 8 },
        bodyStyles: { fontSize: 7 },
        margin: { left: margin, right: margin },
        tableWidth: contentWidth,
      });
      y = (doc as any).lastAutoTable.finalY + 5;
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
            const p = (hookData.cell.raw as string).toLowerCase();
            hookData.cell.styles.textColor = riskColor(p);
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
  doc.text('This report covers non-human identities discovered via the Microsoft Graph API and Azure Resource Manager:', margin, y);
  y += 8;

  const methodLines = [
    '1. SPN Discovery: Enumerate all service principals, managed identities, and app registrations via Microsoft Graph.',
    '2. Credential Audit: Analyze key and certificate credentials for expiry, rotation compliance, and hygiene.',
    '3. Blast Radius Assessment: Classify SPNs by scope of Azure RBAC access (subscription/RG/resource level).',
    '4. Critical Role Detection: Flag SPNs with Owner, Contributor, User Access Administrator, or Global Admin roles.',
    '5. Activity Correlation: Cross-reference sign-in logs to identify dormant, stale, or never-used SPNs.',
    '6. Risk Scoring: Points-based scoring incorporating role criticality, credential health, activity, and ownership.',
    '7. Threat Modeling: Generate attacker narratives showing exploitation paths for high-risk SPNs.',
    '8. Compliance Mapping: Surface audit questions aligned to SOC 2, HIPAA, and NIST 800-53 controls.',
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
  doc.save(`${safeName}_SPN_Privilege_Report_${dateStr}.pdf`);
}
