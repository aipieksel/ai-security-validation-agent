// Findings taxonomy: the normalized vulnerability model shared by the
// reconnaissance and validation presets. Ported and generalized from the
// historical scanner's add_finding() severity/CVSS/remediation structure,
// with confidence and evidence-reference fields added for reproducibility.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEVERITY_ORDER = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

// Confidence reflects how strongly evidence supports a finding. A finding
// backed only by an HTTP status is a hypothesis, not a confirmed issue.
export const CONFIDENCES = ['confirmed', 'probable', 'possible', 'unverified'];
export const CONFIDENCE_ORDER = Object.fromEntries(CONFIDENCES.map((c, i) => [c, i]));

export const CATEGORIES = [
  'dns', 'email', 'headers', 'tls', 'cors', 'subdomain', 'endpoint',
  'supabase', 'storage', 'exposure', 'rate-limiting', 'secrets', 'other',
];

// Category -> default CVSS v3.1 base score used when a more precise vector
// is not available. These mirror the scanner's severity-to-score mapping.
export const CATEGORY_CVSS = {
  dns: 5.0, email: 7.5, headers: 7.0, tls: 7.5, cors: 7.5, subdomain: 5.0,
  endpoint: 7.0, supabase: 9.0, storage: 7.0, exposure: 7.0,
  'rate-limiting': 9.0, secrets: 8.0, other: 5.0,
};

export function severityFromCvss(cvss) {
  if (cvss >= 9.0) return 'CRITICAL';
  if (cvss >= 7.0) return 'HIGH';
  if (cvss >= 4.0) return 'MEDIUM';
  if (cvss > 0) return 'LOW';
  return 'INFO';
}

export function normalizeSeverity(value) {
  const upper = String(value || '').toUpperCase();
  if (SEVERITIES.includes(upper)) return upper;
  return 'INFO';
}

export function normalizeConfidence(value) {
  const lower = String(value || '').toLowerCase();
  if (CONFIDENCES.includes(lower)) return lower;
  return 'unverified';
}

// A normalized finding. `evidence` is a list of references into the artifacts
// directory; `confidence` reflects evidence strength, never the model's mood.
export function createFinding({
  id, title, description, remediation, severity, cvss, category = 'other',
  confidence = 'unverified', evidence = [], asset = null, source = null,
  needsOwnerVerification = false, metadata = {},
}) {
  const score = Number(cvss ?? CATEGORY_CVSS[category] ?? 5.0);
  return {
    id: id ?? `F${Math.random().toString(36).slice(2, 10)}`,
    title: String(title || 'Untitled finding'),
    description: String(description || ''),
    remediation: String(remediation || ''),
    severity: normalizeSeverity(severity) === 'INFO' && score > 0 ? severityFromCvss(score) : normalizeSeverity(severity),
    cvss: score,
    category,
    confidence: normalizeConfidence(confidence),
    evidence: Array.isArray(evidence) ? evidence : [],
    asset: asset ?? null,
    source: source ?? null,
    needsOwnerVerification: Boolean(needsOwnerVerification),
    metadata: metadata ?? {},
  };
}

// Deduplicate findings that describe the same issue on the same asset.
// Two findings match when title and asset agree; the higher-confidence and
// higher-severity instance wins and its evidence is merged.
export function dedupeFindings(findings) {
  const index = new Map();
  for (const finding of findings) {
    const key = `${finding.asset ?? ''}\u0000${finding.title}`;
    const existing = index.get(key);
    if (!existing) {
      index.set(key, finding);
      continue;
    }
    const merged = { ...existing };
    merged.evidence = [...new Set([...existing.evidence, ...finding.evidence])];
    if (CONFIDENCE_ORDER[finding.confidence] < CONFIDENCE_ORDER[existing.confidence]) {
      merged.confidence = finding.confidence;
      merged.description = finding.description;
    }
    if (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[existing.severity]) {
      merged.severity = finding.severity;
      merged.cvss = finding.cvss;
    }
    index.set(key, merged);
  }
  return [...index.values()];
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    || CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence]
    || b.cvss - a.cvss
    || a.title.localeCompare(b.title));
}

export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  return { total: findings.length, ...counts };
}
