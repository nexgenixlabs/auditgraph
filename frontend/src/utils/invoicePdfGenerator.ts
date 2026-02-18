/**
 * AuditGraph Invoice PDF Generator
 *
 * Generates professional B2B invoices using jsPDF + autotable.
 * Matches the existing pdfGenerator.ts patterns.
 */
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// Extend jsPDF type for autotable
declare module 'jspdf' {
  interface jsPDF {
    lastAutoTable: { finalY: number };
  }
}

export interface InvoiceLineItem {
  label: string;
  amount_cents: number;
  type: string;
  cloud?: string;
  count?: number;
}

export interface Invoice {
  id: number;
  tenant_id: number;
  tenant_name?: string;
  invoice_number: string;
  status: string;
  period_start: string;
  period_end: string;
  subtotal_cents: number;
  tax_label: string | null;
  tax_rate: number;
  tax_amount_cents: number;
  discount_cents: number;
  total_cents: number;
  line_items: InvoiceLineItem[];
  seller_snapshot: {
    company_name?: string;
    address?: string;
    email?: string;
    phone?: string;
    tax_id?: string;
  };
  buyer_snapshot: {
    company_name?: string;
    address_line1?: string;
    address_line2?: string;
    city?: string;
    state?: string;
    postal_code?: string;
    country?: string;
    email?: string;
    tax_id?: string;
  };
  issued_at: string | null;
  due_at: string | null;
  paid_at: string | null;
  notes: string | null;
  payment_terms: number;
}

function formatCentsExact(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

function formatShortDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function generateInvoicePdf(invoice: Invoice): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const seller = invoice.seller_snapshot || {};
  const buyer = invoice.buyer_snapshot || {};

  // ─── Header ────────────────────────────────────────────────
  doc.setFillColor(17, 24, 39); // slate-900
  doc.rect(0, 0, pageWidth, 42, 'F');

  // Company name
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text(seller.company_name || 'AuditGraph', margin, 18);

  // Seller details (right-aligned)
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  const sellerLines: string[] = [];
  if (seller.address) sellerLines.push(seller.address);
  if (seller.email) sellerLines.push(seller.email);
  if (seller.phone) sellerLines.push(seller.phone);
  if (seller.tax_id) sellerLines.push(`Tax ID: ${seller.tax_id}`);
  sellerLines.forEach((line, i) => {
    doc.text(line, pageWidth - margin, 14 + i * 4, { align: 'right' });
  });

  // "INVOICE" label
  doc.setTextColor(156, 163, 175); // gray-400
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('INVOICE', margin, 34);

  // Invoice number
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(14);
  doc.text(invoice.invoice_number, margin + 22, 34);

  // Status badge (right)
  const statusColors: Record<string, [number, number, number]> = {
    draft: [107, 114, 128],
    sent: [59, 130, 246],
    paid: [34, 197, 94],
    overdue: [239, 68, 68],
    void: [107, 114, 128],
  };
  const statusColor = statusColors[invoice.status] || [107, 114, 128];
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
  doc.text(invoice.status.toUpperCase(), pageWidth - margin, 34, { align: 'right' });

  y = 52;

  // ─── Invoice Details + Bill To ─────────────────────────────
  doc.setTextColor(107, 114, 128);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('INVOICE DETAILS', margin, y);
  doc.text('BILL TO', margin + contentWidth / 2, y);
  y += 5;

  // Invoice details (left column)
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(55, 65, 81);
  const details = [
    ['Invoice Date', formatShortDate(invoice.issued_at)],
    ['Due Date', formatShortDate(invoice.due_at)],
    ['Payment Terms', `Net ${invoice.payment_terms}`],
    ['Period', `${formatShortDate(invoice.period_start)} — ${formatShortDate(invoice.period_end)}`],
  ];
  details.forEach(([label, value], i) => {
    doc.setTextColor(107, 114, 128);
    doc.text(label, margin, y + i * 5);
    doc.setTextColor(17, 24, 39);
    doc.text(value, margin + 32, y + i * 5);
  });

  // Bill To (right column)
  const rightX = margin + contentWidth / 2;
  let billY = y;
  doc.setTextColor(17, 24, 39);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.text(buyer.company_name || '—', rightX, billY);
  billY += 4.5;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(55, 65, 81);
  const buyerLines: string[] = [];
  if (buyer.address_line1) buyerLines.push(buyer.address_line1);
  if (buyer.address_line2) buyerLines.push(buyer.address_line2);
  const cityState = [buyer.city, buyer.state, buyer.postal_code].filter(Boolean).join(', ');
  if (cityState) buyerLines.push(cityState);
  if (buyer.country) buyerLines.push(buyer.country);
  if (buyer.email) buyerLines.push(buyer.email);
  if (buyer.tax_id) buyerLines.push(`Tax ID: ${buyer.tax_id}`);
  buyerLines.forEach((line) => {
    doc.text(line, rightX, billY);
    billY += 4;
  });

  y += 28;

  // ─── Line Items Table ──────────────────────────────────────
  const nonTaxItems = invoice.line_items.filter(li => li.type !== 'tax');
  const tableData = nonTaxItems.map(li => [
    li.label,
    li.amount_cents < 0
      ? `(${formatCentsExact(Math.abs(li.amount_cents))})`
      : formatCentsExact(li.amount_cents),
  ]);

  autoTable(doc, {
    startY: y,
    head: [['Description', 'Amount']],
    body: tableData,
    margin: { left: margin, right: margin },
    styles: {
      fontSize: 9,
      cellPadding: 3,
      textColor: [17, 24, 39],
      lineColor: [229, 231, 235],
      lineWidth: 0.1,
    },
    headStyles: {
      fillColor: [243, 244, 246],
      textColor: [75, 85, 99],
      fontStyle: 'bold',
      fontSize: 8,
    },
    columnStyles: {
      0: { cellWidth: contentWidth * 0.7 },
      1: { cellWidth: contentWidth * 0.3, halign: 'right' },
    },
    alternateRowStyles: { fillColor: [249, 250, 251] },
  });

  y = doc.lastAutoTable.finalY + 8;

  // ─── Totals Section ────────────────────────────────────────
  const totalsX = pageWidth - margin - 70;
  const valuesX = pageWidth - margin;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  // Subtotal
  doc.setTextColor(107, 114, 128);
  doc.text('Subtotal', totalsX, y);
  doc.setTextColor(17, 24, 39);
  doc.text(formatCentsExact(invoice.subtotal_cents), valuesX, y, { align: 'right' });
  y += 6;

  // Discount (if any)
  if (invoice.discount_cents > 0) {
    doc.setTextColor(107, 114, 128);
    doc.text('Discount', totalsX, y);
    doc.setTextColor(22, 163, 74); // green-600
    doc.text(`(${formatCentsExact(invoice.discount_cents)})`, valuesX, y, { align: 'right' });
    y += 6;
  }

  // Tax
  if (invoice.tax_amount_cents > 0) {
    const taxLabel = invoice.tax_label
      ? `${invoice.tax_label} (${invoice.tax_rate}%)`
      : `Tax (${invoice.tax_rate}%)`;
    doc.setTextColor(107, 114, 128);
    doc.text(taxLabel, totalsX, y);
    doc.setTextColor(17, 24, 39);
    doc.text(formatCentsExact(invoice.tax_amount_cents), valuesX, y, { align: 'right' });
    y += 6;
  }

  // Divider
  doc.setDrawColor(209, 213, 219);
  doc.setLineWidth(0.3);
  doc.line(totalsX, y, valuesX, y);
  y += 5;

  // Total
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(17, 24, 39);
  doc.text('Total Due', totalsX, y);
  doc.text(formatCentsExact(invoice.total_cents), valuesX, y, { align: 'right' });
  y += 4;

  // Currency note
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(156, 163, 175);
  doc.text('USD', valuesX, y, { align: 'right' });

  // ─── Notes ─────────────────────────────────────────────────
  if (invoice.notes) {
    y += 12;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(107, 114, 128);
    doc.text('NOTES', margin, y);
    y += 4;
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(55, 65, 81);
    const noteLines = doc.splitTextToSize(invoice.notes, contentWidth);
    doc.text(noteLines, margin, y);
  }

  // ─── Footer ────────────────────────────────────────────────
  const footerY = doc.internal.pageSize.getHeight() - 15;
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(0.2);
  doc.line(margin, footerY - 5, pageWidth - margin, footerY - 5);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(156, 163, 175);
  doc.text('Thank you for your business.', pageWidth / 2, footerY, { align: 'center' });
  doc.text(`Generated ${new Date().toLocaleDateString()}`, pageWidth / 2, footerY + 4, { align: 'center' });

  // ─── Save ──────────────────────────────────────────────────
  doc.save(`${invoice.invoice_number}.pdf`);
}
