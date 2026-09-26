// Ingest a reconnaissance report and artifacts into normalized findings.
// This is the deterministic bridge: the reconnaissance preset writes prose
// (RECON_REPORT.md) and artifacts; this module extracts structured findings
// and hypotheses without contacting any network resource.

import { readFile, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { createFinding, dedupeFindings, sortFindings, summarize, normalizeSeverity, normalizeConfidence } from './findings.mjs';
import { FINGERPRINTS, fingerprint, checkSecurityHeaders } from './fingerprints.mjs';
import { emptyFindingsDoc } from './schema.mjs';

const SEVERITY_RE = /\b(critical|high|medium|low|info)\b/gi;
const CVSS_RE = /\bcvss[:\s]*([0-9](?:\.[0-9])?)/gi;
const CONFIDENCE_RE = /\b(confirmed|probable|possible|unverified)\b/gi;
const URL_RE = /https?:\/\/[^\s"'<>)]+/g;
const HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

const SECRET_PATTERNS = [
  /sb_publishable_[A-Za-z0-9_-]+/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{24,})\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];

const SENSITIVE_FIELD_RE = /\b(password|secret|token|api[_-]?key|private[_-]?key|authorization|bearer|cookie)\b/i;

function redact(text) {
  let out = String(text ?? '');
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, '[REDACTED]');
  return out;
}

function extractHeaderObservations(text) {
  // Parse "Header: value" or "Header: Missing" lines, tolerating Markdown
  // list bullets ("- Header: Missing") and bold markers.
  const observations = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const match = line.match(/^\s*(?:[-*]\s+|\*\*)?(Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Content-Security-Policy|Permissions-Policy|Cross-Origin-Opener-Policy|Cross-Origin-Embedder-Policy|Cross-Origin-Resource-Policy)\s*:\s*(.+?)\**\s*$/i);
    if (match) {
      const name = match[1];
      const raw = match[2].trim();
      const missing = /missing|absent|none|^\s*$/i.test(raw);
      observations.push({ name, present: !missing, value: missing ? null : raw });
    }
  }
  return observations;
}

function extractHosts(text) {
  const hosts = new Set();
  for (const match of String(text ?? '').matchAll(URL_RE)) {
    try { hosts.add(new URL(match[0]).hostname); } catch { /* ignore malformed */ }
  }
  for (const match of String(text ?? '').matchAll(HOST_RE)) {
    if (!/\d{1,3}(?:\.\d{1,3}){3}/.test(match[0])) hosts.add(match[0]);
  }
  return [...hosts];
}

// Convert a list of header observations into findings using the shared policy.
function findingsFromHeaders(observations, asset, evidence) {
  return observations
    .filter(obs => !obs.present)
    .map(obs => {
      const policy = (checkSecurityHeaders({})).find(h => h.name === obs.name);
      return createFinding({
        title: `Missing ${obs.name} on ${asset ?? 'target'}`,
        description: policy?.description ?? `${obs.name} header is absent`,
        remediation: `Add: ${obs.name}: ${policy?.recommended ?? 'a suitable value'}`,
        severity: policy?.severity ?? 'MEDIUM',
        cvss: policy?.cvss ?? 5.0,
        category: 'headers',
        confidence: 'confirmed',
        evidence,
        asset,
        source: 'reconnaissance-report',
      });
    });
}

function findingsFromSecrets(text, asset, evidence) {
  return SECRET_PATTERNS.map(pattern => {
    const match = String(text ?? '').match(pattern);
    if (!match) return null;
    return createFinding({
      title: `Exposed secret in client bundle`,
      description: `A secret-like value matching a known pattern was observed.`,
      remediation: 'Rotate the exposed secret and remove it from client-side code.',
      severity: 'HIGH', cvss: 8.0, category: 'secrets',
      confidence: 'probable', evidence, asset, source: 'reconnaissance-report',
    });
  }).filter(Boolean);
}

// Search a report for severity/confidence/title triples and synthesize
// findings for lines that carry a severity and a remediation hint.
function findingsFromProse(text, evidence) {
  const findings = [];
  const lines = String(text ?? '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const severityMatch = line.match(SEVERITY_RE);
    if (!severityMatch) continue;
    const severity = normalizeSeverity(severityMatch[0]);
    const title = line.replace(SEVERITY_RE, '').replace(/^[^a-z0-9]*[-:*]\s*/, '').trim().slice(0, 140);
    if (!title) continue;
    const cvssMatch = line.match(CVSS_RE);
    const confidence = (line.match(CONFIDENCE_RE) || [])[0] || 'unverified';
    findings.push(createFinding({
      title,
      description: 'Reported by the reconnaissance agent; verify against artifacts.',
      remediation: 'Review the referenced artifact and confirm the observation.',
      severity,
      cvss: cvssMatch ? Number(cvssMatch[1]) : undefined,
      category: 'other',
      confidence: normalizeConfidence(confidence),
      evidence,
      source: 'reconnaissance-report',
    }));
  }
  return findings;
}

async function readArtifacts(dir) {
  let entries = [];
  try { entries = await readdir(dir); } catch { return []; }
  const loaded = [];
  for (const entry of entries) {
    const path = join(dir, entry);
    const ext = extname(entry).toLowerCase();
    if (!['.txt', '.md', '.json', '.log', '.html'].includes(ext)) continue;
    try {
      const content = await readFile(path, 'utf8');
      loaded.push({ name: entry, content: content.slice(0, 200_000) });
    } catch { /* skip unreadable artifact */ }
  }
  return loaded;
}

// Ingest a reconnaissance report directory into a normalized findings document.
// `dir` is the mission workspace; it reads RECON_REPORT.md and the artifacts/
// subdirectory (if present). No network access is performed.
export async function ingest({ dir, target = null, artifactsDir = 'artifacts' } = {}) {
  const doc = emptyFindingsDoc({ target });
  let reportText = '';
  let reportEvidence = 'RECON_REPORT.md';
  try {
    reportText = await readFile(join(dir, 'RECON_REPORT.md'), 'utf8');
  } catch {
    // A missing report is not fatal; the caller can still run safe checks.
    reportEvidence = null;
  }

  const artifacts = await readArtifacts(join(dir, artifactsDir));
  const hosts = extractHosts(reportText);
  const asset = target ?? hosts[0] ?? null;
  const evidence = reportEvidence ? [reportEvidence] : [];
  if (!doc.target && asset) doc.target = asset;

  const docFindings = [];
  docFindings.push(...findingsFromHeaders(extractHeaderObservations(reportText), asset, evidence));
  docFindings.push(...findingsFromSecrets(reportText, asset, evidence));
  docFindings.push(...findingsFromProse(reportText, evidence));

  // Artifact-based observations: secrets and fingerprints in captured files.
  for (const artifact of artifacts) {
    docFindings.push(...findingsFromSecrets(artifact.content, asset, [`${artifactsDir}/${artifact.name}`]));
  }

  doc.findings = sortFindings(dedupeFindings(docFindings));
  doc.summary = summarize(doc.findings);
  doc.assets = {
    hosts,
    fingerprints: fingerprint({ body: reportText }),
    artifacts: artifacts.map(a => a.name),
  };
  return doc;
}
