// Deterministic security checks that consume Probe results and emit findings.
// Ported from the historical scanner's phase logic, with two correctness fixes:
//   1. An SPA "catch-all" route (every path returns the same 200 HTML) is NOT
//      treated as an exposed endpoint — the scanner wrongly flagged /api/*,
//      /admin, and /actuator/* as vulnerable because the app served index.html.
//   2. Supabase "permission denied" (42501) and "function not found" (PGRST202)
//      responses are protective outcomes, not data leaks.

import { createFinding } from './findings.mjs';
import { checkSecurityHeaders } from './fingerprints.mjs';

// Paths worth probing for exposure. Presence is confirmed only when the
// response is distinguishable from the site's SPA catch-all.
export const COMMON_PATHS = [
  '/', '/robots.txt', '/sitemap.xml', '/manifest.json', '/sw.js',
  '/.env', '/.git/config', '/.git/HEAD', '/admin', '/login',
  '/server-status', '/swagger-ui.html', '/api-docs', '/actuator/health',
  '/health', '/status', '/metrics',
];

const SENSITIVE_PATHS = new Set(['/.env', '/.git/config', '/.git/HEAD', '/server-status', '/actuator/env', '/actuator/metrics', '/actuator/trace']);

// Heuristic: does this body look like the site's index.html (SPA catch-all)?
function looksLikeCatchAll(body, contentType) {
  const text = String(body ?? '');
  const ct = String(contentType ?? '').toLowerCase();
  if (ct.includes('text/html') && /<!doctype html>/i.test(text.slice(0, 200))) {
    // A real SPA serves its shell for unknown routes. Treat a 200 HTML shell
    // as a catch-all only when the body is large enough to be a full document.
    return text.length > 500;
  }
  return false;
}

export function checkEndpoints(results, { asset, allowlist = [] } = {}) {
  const findings = [];
  const samples = [];
  for (const result of results) {
    if (result.error) continue;
    const isSensitive = SENSITIVE_PATHS.has(result.path);
    const catchAll = looksLikeCatchAll(result.body, result.contentType);
    if (result.status === 200 && !catchAll) {
      samples.push({ path: result.path, status: result.status, contentType: result.contentType });
      if (isSensitive) {
        findings.push(createFinding({
          title: `Sensitive path exposed: ${result.path}`,
          description: `${result.path} returned HTTP 200 with a distinct, non-shell response.`,
          remediation: `Block access to ${result.path} and review its contents.`,
          severity: 'HIGH', cvss: 7.5, category: 'exposure',
          confidence: 'confirmed', evidence: [result.path], asset,
        }));
      } else {
        findings.push(createFinding({
          title: `Publicly accessible path: ${result.path}`,
          description: `${result.path} returned HTTP 200.`,
          remediation: 'Confirm the path is intended to be public.',
          severity: 'INFO', cvss: 0.0, category: 'endpoint',
          confidence: 'confirmed', evidence: [result.path], asset,
        }));
      }
    }
  }
  return { findings, samples };
}

export function checkHeaders(headerResults, { asset } = {}) {
  const findings = [];
  for (const result of headerResults) {
    if (result.present) continue;
    findings.push(createFinding({
      title: `Missing ${result.name} on ${asset ?? 'target'}`,
      description: result.description,
      remediation: `Add: ${result.name}: ${result.recommended}`,
      severity: result.severity, cvss: result.cvss, category: 'headers',
      confidence: 'confirmed', evidence: [`headers:${result.name}`], asset,
    }));
  }
  return findings;
}

export function checkDns(dnsResult, { asset } = {}) {
  const findings = [];
  const txt = (dnsResult?.TXT ?? []).flat().join('');
  const hasSpf = /v=spf1/i.test(txt);
  const hasDmarc = /v=dmarc/i.test(txt);
  if (!hasSpf) {
    findings.push(createFinding({
      title: 'Missing SPF record',
      description: 'Email spoofing possible.',
      remediation: 'Add a TXT record: v=spf1 include:_spf.example.com ~all',
      severity: 'HIGH', cvss: 7.5, category: 'email',
      confidence: 'confirmed', evidence: ['dns:TXT'], asset,
    }));
  }
  if (!hasDmarc) {
    findings.push(createFinding({
      title: 'Missing DMARC record',
      description: 'Email spoofing and phishing possible.',
      remediation: 'Add a TXT record: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
      severity: 'HIGH', cvss: 7.5, category: 'email',
      confidence: 'confirmed', evidence: ['dns:TXT'], asset,
    }));
  }
  if (dnsResult?.CAA === null || (Array.isArray(dnsResult?.CAA) && dnsResult.CAA.length === 0)) {
    findings.push(createFinding({
      title: 'Missing CAA record',
      description: 'Any CA may issue certificates for the domain.',
      remediation: 'Add a CAA record restricting issuance to your CA.',
      severity: 'MEDIUM', cvss: 5.0, category: 'dns',
      confidence: 'confirmed', evidence: ['dns:CAA'], asset,
    }));
  }
  return findings;
}

export function checkCors(corsResults, { asset } = {}) {
  const findings = [];
  for (const result of corsResults) {
    if (!result.allowOrigin) continue;
    if (result.allowOrigin === '*') {
      findings.push(createFinding({
        title: `CORS allows all origins on ${asset ?? 'target'}`,
        description: 'Any website can make cross-origin requests.',
        remediation: 'Restrict Access-Control-Allow-Origin to trusted origins.',
        severity: 'HIGH', cvss: 7.5, category: 'cors',
        confidence: 'confirmed', evidence: ['cors:access-control-allow-origin'], asset,
      }));
    }
  }
  return findings;
}

export function checkTlsProtocols(protocolResults, { asset } = {}) {
  const findings = [];
  for (const result of protocolResults) {
    if (result.enabled) {
      findings.push(createFinding({
        title: `Weak TLS protocol enabled: ${result.protocol}`,
        description: `${result.protocol} is accepted by the server.`,
        remediation: `Disable ${result.protocol} on the server.`,
        severity: 'HIGH', cvss: 7.5, category: 'tls',
        confidence: 'confirmed', evidence: [`tls:${result.protocol}`], asset,
      }));
    }
  }
  return findings;
}

// Interpret a Supabase REST/RPC response. Returns a protective status when the
// response indicates permission denial or a missing function.
export function interpretSupabase({ status, body }) {
  const text = String(body ?? '');
  if (status === 401 || status === 403) return { protective: true, reason: `HTTP ${status}` };
  if (/42501|permission denied/i.test(text)) return { protective: true, reason: 'permission denied (RLS)' };
  if (/PGRST202|no matches were found/i.test(text)) return { protective: true, reason: 'function not found' };
  if (status === 200 && text.trim() && text.trim() !== '[]' && text.trim() !== 'null') {
    return { protective: false, reason: 'returned data' };
  }
  return { protective: true, reason: 'empty or null response' };
}

export function checkSupabaseTable({ table, status, body }, { asset } = {}) {
  const result = interpretSupabase({ status, body });
  if (!result.protective) {
    return createFinding({
      title: `Supabase table exposed to anonymous access: ${table}`,
      description: `Table ${table} returned data without authentication.`,
      remediation: 'Enable Row Level Security and restrict SELECT policies.',
      severity: 'CRITICAL', cvss: 9.5, category: 'supabase',
      confidence: 'confirmed', evidence: [`supabase:${table}`], asset,
    });
  }
  return null;
}
