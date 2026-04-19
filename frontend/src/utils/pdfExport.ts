import jsPDF from 'jspdf';
import { AnalysisResult, SeverityLevel } from '../types';

const SEVERITY_COLOR: Record<SeverityLevel, [number, number, number]> = {
  HIGH: [220, 38, 38],
  MEDIUM: [234, 88, 12],
  LOW: [202, 138, 4],
  INFO: [59, 130, 246],
};

export function exportToPDF(result: AnalysisResult): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 18;
  const contentW = pageW - margin * 2;
  let y = margin;

  const addPage = () => {
    doc.addPage();
    y = margin;
  };

  const checkY = (needed: number) => {
    if (y + needed > 275) addPage();
  };

  // ── Header ──────────────────────────────────────────────
  doc.setFillColor(17, 24, 39);
  doc.rect(0, 0, pageW, 38, 'F');

  doc.setFontSize(22);
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.text('ChainGuard', margin, 18);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(156, 163, 175);
  doc.text('Security Audit Report', margin, 26);
  doc.text('HackOWASP 8.0', pageW - margin, 26, { align: 'right' });

  y = 48;

  // ── Meta ────────────────────────────────────────────────
  doc.setFontSize(11);
  doc.setTextColor(55, 65, 81);
  doc.setFont('helvetica', 'bold');
  doc.text('Contract:', margin, y);
  doc.setFont('helvetica', 'normal');
  doc.text(result.contractName, margin + 28, y);
  y += 7;

  doc.setFont('helvetica', 'bold');
  doc.text('Analyzed:', margin, y);
  doc.setFont('helvetica', 'normal');
  doc.text(new Date(result.analyzedAt).toLocaleString(), margin + 28, y);
  y += 7;

  doc.setFont('helvetica', 'bold');
  doc.text('Issues found:', margin, y);
  doc.setFont('helvetica', 'normal');
  doc.text(String(result.totalFound), margin + 35, y);
  y += 12;

  // ── Score ───────────────────────────────────────────────
  const scoreColor: [number, number, number] =
    result.score >= 80 ? [34, 197, 94] : result.score >= 50 ? [234, 179, 8] : [239, 68, 68];

  doc.setFillColor(...scoreColor);
  doc.roundedRect(margin, y, 40, 18, 3, 3, 'F');
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(255, 255, 255);
  doc.text(String(result.score), margin + 20, y + 12, { align: 'center' });

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(107, 114, 128);
  doc.text('Security Score / 100', margin + 44, y + 7);
  y += 26;

  // ── Divider ─────────────────────────────────────────────
  doc.setDrawColor(229, 231, 235);
  doc.line(margin, y, pageW - margin, y);
  y += 8;

  // ── Vulnerability list ───────────────────────────────────
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(17, 24, 39);
  doc.text('Findings', margin, y);
  y += 8;

  if (result.vulnerabilities.length === 0) {
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(34, 197, 94);
    doc.text('No vulnerabilities detected. Contract passed all security checks.', margin, y);
    y += 10;
  }

  result.vulnerabilities.forEach((vuln, i) => {
    checkY(40);

    const [r, g, b] = SEVERITY_COLOR[vuln.severity];

    // Severity badge
    doc.setFillColor(r, g, b);
    doc.roundedRect(margin, y, 22, 7, 1.5, 1.5, 'F');
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(255, 255, 255);
    doc.text(vuln.severity, margin + 11, y + 4.5, { align: 'center' });

    // Title
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(17, 24, 39);
    doc.text(`${i + 1}. ${vuln.title}`, margin + 25, y + 5);

    // SWC + line
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(107, 114, 128);
    const meta = [vuln.swcId, vuln.line !== null ? `Line ${vuln.line}` : null]
      .filter(Boolean)
      .join(' · ');
    doc.text(meta, pageW - margin, y + 5, { align: 'right' });
    y += 11;

    // Description (HIGH only — to keep report concise)
    if (vuln.severity === 'HIGH' || vuln.severity === 'MEDIUM') {
      checkY(20);
      const descLines = doc.splitTextToSize(vuln.description, contentW);
      doc.setFontSize(8.5);
      doc.setTextColor(55, 65, 81);
      doc.text(descLines, margin, y);
      y += descLines.length * 4.5 + 2;

      // Recommendation
      checkY(14);
      doc.setFontSize(8);
      doc.setTextColor(21, 128, 61);
      doc.setFont('helvetica', 'bold');
      doc.text('Fix: ', margin, y);
      doc.setFont('helvetica', 'normal');
      const recLines = doc.splitTextToSize(vuln.recommendation, contentW - 10);
      doc.text(recLines, margin + 8, y);
      y += recLines.length * 4.5 + 4;
    }

    doc.setDrawColor(243, 244, 246);
    doc.line(margin, y, pageW - margin, y);
    y += 5;
  });

  // ── Footer ───────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages();
  for (let p = 1; p <= pageCount; p++) {
    doc.setPage(p);
    doc.setFontSize(8);
    doc.setTextColor(156, 163, 175);
    doc.text(
      `Generated by ChainGuard — HackOWASP 8.0  ·  Page ${p} of ${pageCount}`,
      pageW / 2,
      290,
      { align: 'center' }
    );
  }

  doc.save(`chainguard-report-${result.contractName}-${Date.now()}.pdf`);
}
