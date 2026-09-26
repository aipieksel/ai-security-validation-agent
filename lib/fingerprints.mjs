// Technology and service fingerprinting rules ported and generalized from the
// historical scanner. Each rule maps observable evidence (headers, cookies,
// response bodies, DNS records) to a technology hypothesis with a confidence
// and a list of alternative explanations. A fingerprint is a hypothesis, not
// a vulnerability.

export const FINGERPRINTS = [
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    match: headers => Boolean(headers['cf-ray'] || headers['server']?.toLowerCase().includes('cloudflare')),
    evidence: 'cf-ray or server header',
  },
  {
    id: 'supabase',
    name: 'Supabase',
    match: (headers, body) => /sb_publishable_|supabase\.co|rest\/v1|auth\/v1/.test(body ?? ''),
    evidence: 'Supabase key or API path in client bundle',
  },
  {
    id: 'react',
    name: 'React SPA',
    match: (headers, body) => /react|__NEXT_DATA__|data-reactroot|createRoot/i.test(body ?? ''),
    evidence: 'React runtime markers in HTML',
  },
  {
    id: 'google-trust-services',
    name: 'Google Trust Services (TLS)',
    match: (headers, body, tls) => /Google Trust Services/i.test(tls?.issuer ?? ''),
    evidence: 'certificate issuer',
  },
  {
    id: 'sentry',
    name: 'Sentry',
    match: (headers, body) => /sentry\.io|SENTRY_DSN|o\d+\.ingest\.sentry/i.test(body ?? ''),
    evidence: 'Sentry DSN or ingest host in client bundle',
  },
  {
    id: 'cloudflare-r2',
    name: 'Cloudflare R2 storage',
    match: (headers, body) => /r2\.dev|\.r2\.cloudflarestorage\.com/.test(body ?? ''),
    evidence: 'R2 object URLs in HTML',
  },
];

export function fingerprint({ headers = {}, body = '', tls = {} } = {}) {
  const matches = [];
  for (const rule of FINGERPRINTS) {
    try {
      if (rule.match(headers, body, tls)) {
        matches.push({ id: rule.id, name: rule.name, evidence: rule.evidence });
      }
    } catch {
      // A fingerprint rule must never throw; ignore malformed inputs.
    }
  }
  return matches;
}

// Security header policy: recommended value and remediation guidance per header.
export const SECURITY_HEADERS = {
  'Strict-Transport-Security': {
    recommended: 'max-age=31536000; includeSubDomains',
    severity: 'HIGH', cvss: 7.5,
    description: 'HTTPS downgrade possible',
  },
  'X-Frame-Options': {
    recommended: 'DENY',
    severity: 'HIGH', cvss: 7.0,
    description: 'Clickjacking vulnerability',
  },
  'X-Content-Type-Options': {
    recommended: 'nosniff',
    severity: 'MEDIUM', cvss: 5.0,
    description: 'MIME type sniffing possible',
  },
  'Referrer-Policy': {
    recommended: 'strict-origin-when-cross-origin',
    severity: 'MEDIUM', cvss: 5.0,
    description: 'Information leakage via referrer headers',
  },
  'Content-Security-Policy': {
    recommended: "default-src 'self'",
    severity: 'HIGH', cvss: 7.5,
    description: 'XSS vulnerability — no content security policy',
  },
  'Permissions-Policy': {
    recommended: 'geolocation=(), microphone=(), camera=()',
    severity: 'MEDIUM', cvss: 5.0,
    description: 'Browser features not restricted',
  },
  'Cross-Origin-Opener-Policy': {
    recommended: 'same-origin',
    severity: 'MEDIUM', cvss: 5.0,
    description: 'Cross-origin window isolation absent',
  },
  'Cross-Origin-Embedder-Policy': {
    recommended: 'require-corp',
    severity: 'MEDIUM', cvss: 5.0,
    description: 'Cross-origin resource embedding unrestricted',
  },
  'Cross-Origin-Resource-Policy': {
    recommended: 'same-site',
    severity: 'MEDIUM', cvss: 5.0,
    description: 'Cross-origin resource loading unrestricted',
  },
};

export function checkSecurityHeaders(headers = {}, asset = null) {
  const results = [];
  for (const [name, policy] of Object.entries(SECURITY_HEADERS)) {
    const value = headers[name];
    if (value == null) {
      results.push({
        name, present: false, value: null,
        recommended: policy.recommended,
        severity: policy.severity, cvss: policy.cvss,
        description: policy.description,
      });
    } else {
      results.push({ name, present: true, value, recommended: policy.recommended });
    }
  }
  return results;
}
