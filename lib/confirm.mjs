// Authorized confirmation capability.
// Re-checks existing findings against allowlisted hosts using the same
// GET/HEAD-only probe. This is not exploitation: no payloads, writes,
// credential guessing, or off-allowlist hosts.

import { createFinding } from './findings.mjs';

export function headerValues(headers, name) {
  if (!headers) return [];
  const lower = name.toLowerCase();
  const raw = headers[name] ?? headers[lower];
  if (raw == null) return [];
  return Array.isArray(raw) ? raw.map(String) : [String(raw)];
}

export function pathFromFinding(finding) {
  for (const item of finding?.evidence || []) {
    const value = String(item);
    if (value.startsWith('/')) return value.split(/\s/)[0];
    const colon = value.indexOf(':');
    if (colon >= 0) {
      const rest = value.slice(colon + 1);
      if (rest.startsWith('/')) return rest.split(/\s/)[0];
    }
  }
  const match = String(finding?.title || '').match(/(\/[A-Za-z0-9._~/?#@!$&'()*+,;=%-]*)/);
  return match ? match[1] : null;
}

export function confirmationStatus({ actualStatus, error } = {}) {
  if (error) return 'inconclusive';
  if (actualStatus == null) return 'inconclusive';
  if (actualStatus >= 500) return 'inconclusive';
  if (actualStatus === 200 || actualStatus === 301 || actualStatus === 302 || actualStatus === 303 || actualStatus === 307 || actualStatus === 308) {
    return 'confirmed';
  }
  if (actualStatus === 401 || actualStatus === 403 || actualStatus === 404) return 'not-reproduced';
  return 'inconclusive';
}

export function inspectCookieFlags(headers, { asset } = {}) {
  const findings = [];
  for (const cookie of headerValues(headers, 'set-cookie')) {
    const name = cookie.split('=')[0].trim() || 'cookie';
    const lower = cookie.toLowerCase();
    if (!lower.includes('httponly')) {
      findings.push(createFinding({
        title: `Cookie ${name} missing HttpOnly`,
        description: `Set-Cookie for ${name} does not set HttpOnly.`,
        remediation: `Add HttpOnly to the ${name} cookie.`,
        severity: 'MEDIUM', cvss: 5.3, category: 'headers',
        confidence: 'confirmed', evidence: [`set-cookie:${name}`], asset,
      }));
    }
    if (!lower.includes('secure')) {
      findings.push(createFinding({
        title: `Cookie ${name} missing Secure`,
        description: `Set-Cookie for ${name} does not set Secure.`,
        remediation: `Add Secure to the ${name} cookie.`,
        severity: 'MEDIUM', cvss: 5.3, category: 'headers',
        confidence: 'confirmed', evidence: [`set-cookie:${name}`], asset,
      }));
    }
    if (!lower.includes('samesite')) {
      findings.push(createFinding({
        title: `Cookie ${name} missing SameSite`,
        description: `Set-Cookie for ${name} does not set SameSite.`,
        remediation: `Add SameSite=Lax or Strict to the ${name} cookie.`,
        severity: 'LOW', cvss: 3.1, category: 'headers',
        confidence: 'confirmed', evidence: [`set-cookie:${name}`], asset,
      }));
    }
  }
  return findings;
}

export function redirectStaysOnAllowlist(headers, allowlist = []) {
  const location = headerValues(headers, 'location')[0];
  if (!location) return { redirected: false, allowed: true, host: null };
  try {
    const url = new URL(location, 'https://allowlist.invalid');
    const host = url.hostname.toLowerCase();
    const allowed = allowlist.map((item) => String(item).toLowerCase()).includes(host);
    return { redirected: true, allowed, host };
  } catch {
    return { redirected: true, allowed: false, host: null };
  }
}

export async function confirmAuthorized({
  probe,
  findings = [],
  scheme = 'https',
  host,
  port = null,
} = {}) {
  if (!probe || !host) {
    throw new Error('confirmAuthorized requires probe and host');
  }
  const authority = port ? `${host}:${port}` : host;
  const base = `${scheme}://${authority}`;
  const extraFindings = [];
  const confirmations = [];

  try {
    const head = await probe.request({ url: `${base}/`, method: 'HEAD' });
    extraFindings.push(...inspectCookieFlags(head.headers, { asset: host }));
    const redirect = redirectStaysOnAllowlist(head.headers, [...probe.allowlist]);
    if (redirect.redirected && !redirect.allowed) {
      extraFindings.push(createFinding({
        title: `Redirect left the authorization allowlist: ${redirect.host || 'unknown'}`,
        description: `HEAD / returned a Location host that is not in the authorization allowlist.`,
        remediation: 'Keep redirects on authorized hosts or update the authorization file.',
        severity: 'HIGH', cvss: 7.5, category: 'exposure',
        confidence: 'confirmed', evidence: ['location:/'], asset: host,
      }));
    }
  } catch (error) {
    confirmations.push({
      findingId: null,
      title: 'root HEAD',
      status: 'inconclusive',
      reason: error.message,
    });
  }

  const seen = new Set();
  for (const finding of findings) {
    const path = pathFromFinding(finding);
    if (!path) {
      confirmations.push({
        findingId: finding.id,
        title: finding.title,
        status: 'inconclusive',
        reason: 'no retrievable path',
      });
      continue;
    }
    if (seen.has(path)) continue;
    seen.add(path);
    try {
      const result = await probe.request({ url: `${base}${path}`, method: 'GET' });
      confirmations.push({
        findingId: finding.id,
        title: finding.title,
        path,
        httpStatus: result.status,
        status: confirmationStatus({ actualStatus: result.status }),
      });
    } catch (error) {
      confirmations.push({
        findingId: finding.id,
        title: finding.title,
        path,
        status: 'inconclusive',
        reason: error.message,
      });
    }
  }

  return { extraFindings, confirmations };
}
