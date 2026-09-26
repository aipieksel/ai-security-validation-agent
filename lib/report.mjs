// Report emitters: JSON (machine-readable), Markdown (human), HTML (shareable).
// The HTML layout and severity styling are generalized from the scanner's
// report.html generator.

import { SEVERITIES } from './findings.mjs';

const SEVERITY_COLOR = {
  CRITICAL: '#e74c3c',
  HIGH: '#e67e22',
  MEDIUM: '#f1c40f',
  LOW: '#3498db',
  INFO: '#95a5a6',
};

export function jsonReport(doc) {
  return JSON.stringify(doc, null, 2);
}

export function markdownReport(doc) {
  const lines = [];
  lines.push('# Security Validation Report');
  lines.push('');
  lines.push(`- **Target:** ${doc.target ?? 'unspecified'}`);
  lines.push(`- **Generated:** ${doc.generatedAt}`);
  lines.push(`- **Schema:** ${doc.schemaVersion}`);
  lines.push('');
  lines.push('## Executive summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const severity of SEVERITIES) {
    lines.push(`| ${severity} | ${doc.summary?.[severity] ?? 0} |`);
  }
  lines.push(`| **Total** | ${doc.summary?.total ?? doc.findings.length} |`);
  lines.push('');
  lines.push('## Findings');
  lines.push('');
  if (!doc.findings.length) {
    lines.push('No findings.');
  }
  for (const finding of doc.findings) {
    lines.push(`### [${finding.severity}] ${finding.title}`);
    lines.push('');
    lines.push(`- **CVSS:** ${finding.cvss}`);
    lines.push(`- **Confidence:** ${finding.confidence}`);
    lines.push(`- **Category:** ${finding.category}`);
    lines.push(`- **Asset:** ${finding.asset ?? '—'}`);
    if (finding.evidence.length) lines.push(`- **Evidence:** ${finding.evidence.join(', ')}`);
    lines.push(`- **Description:** ${finding.description}`);
    lines.push(`- **Remediation:** ${finding.remediation}`);
    if (finding.needsOwnerVerification) lines.push('- **Requires owner-controlled verification**');
    lines.push('');
  }
  if (doc.confirmations?.length) {
    lines.push('## Authorized confirmation');
    lines.push('');
    for (const item of doc.confirmations) {
      const path = item.path ? ` ${item.path}` : '';
      const extra = item.reason ? ` — ${item.reason}` : item.httpStatus ? ` — HTTP ${item.httpStatus}` : '';
      lines.push(`- **${item.status}**${path}${extra}`);
    }
    lines.push('');
  }
  if (doc.coverageGaps?.length) {
    lines.push('## Coverage gaps and stop conditions');
    lines.push('');
    for (const gap of doc.coverageGaps) lines.push(`- ${gap}`);
    lines.push('');
  }
  if (doc.ownerVerificationPlans?.length) {
    lines.push('## Owner-controlled verification plans');
    lines.push('');
    for (const plan of doc.ownerVerificationPlans) lines.push(`- ${plan}`);
    lines.push('');
  }
  return lines.join('\n');
}

export function htmlReport(doc) {
  const rows = doc.findings.map(f => `
    <div class="finding severity-${f.severity.toLowerCase()}">
      <div class="title">[${f.severity}] ${escapeHtml(f.title)}</div>
      <div class="meta">CVSS ${f.cvss} · ${f.confidence} · ${f.category} · ${escapeHtml(f.asset ?? '—')}</div>
      <div class="description">${escapeHtml(f.description)}</div>
      <div class="remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>
    </div>`).join('');
  const summary = SEVERITIES.map(s =>
    `<div class="summary-box" style="background:${SEVERITY_COLOR[s]}">${s}: ${doc.summary?.[s] ?? 0}</div>`).join('');
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Security Validation Report</title>
  <style>
    body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 40px; background: #f4f4f4; }
    .container { max-width: 1100px; margin: auto; background: white; padding: 24px; border-radius: 8px; }
    .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .summary { display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }
    .summary-box { flex: 1; min-width: 90px; padding: 14px; border-radius: 4px; text-align: center; color: white; }
    .finding { border-left: 5px solid #ccc; margin: 15px 0; padding: 12px; background: #f9f9f9; }
    .finding.severity-critical { border-color: #e74c3c; }
    .finding.severity-high { border-color: #e67e22; }
    .finding.severity-medium { border-color: #f1c40f; }
    .finding.severity-low { border-color: #3498db; }
    .finding.severity-info { border-color: #95a5a6; }
    .title { font-weight: bold; font-size: 17px; }
    .meta { color: #777; font-size: 13px; margin: 4px 0; }
    .description { margin: 6px 0; }
    .remediation { background: #e8f5e9; padding: 8px; border-radius: 4px; margin-top: 6px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Security Validation Report</h1>
      <p>Target: ${escapeHtml(doc.target ?? 'unspecified')} · Generated: ${escapeHtml(doc.generatedAt)}</p>
    </div>
    <div class="summary">${summary}</div>
    <h2>Findings</h2>
    ${rows || '<p>No findings.</p>'}
  </div>
</body>
</html>`;
}

function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
