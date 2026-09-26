// Enforced, read-only network probe. Unlike the historical scanner, safety is
// enforced here in code, not in a prompt:
//   - only GET and HEAD are permitted; every other method throws.
//   - every target host must be in the authorization allowlist.
//   - a request budget and a minimum interval are enforced.
//   - stop conditions (429, repeated 5xx, redirect off-allowlist) abort the run.
//   - redirects are never followed automatically.

import { lookup, resolveTxt, resolveMx, resolveCaa, resolveAny } from 'node:dns/promises';
import { connect } from 'node:tls';

const DEFAULT_BUDGET = 30;
const DEFAULT_INTERVAL_MS = 1000;
const DEFAULT_TIMEOUT_MS = 5000;

export class ScopeError extends Error {}
export class BudgetExceededError extends Error {}
export class StopConditionError extends Error {}

export class Probe {
  constructor({ allowlist = [], budget = DEFAULT_BUDGET, intervalMs = DEFAULT_INTERVAL_MS, timeoutMs = DEFAULT_TIMEOUT_MS, allowPrivateHosts = false } = {}) {
    this.allowlist = new Set(allowlist.map(h => h.toLowerCase()));
    this.remaining = budget;
    this.intervalMs = intervalMs;
    this.timeoutMs = timeoutMs;
    this.allowPrivateHosts = allowPrivateHosts;
    this.requestCount = 0;
    this.lastRequestAt = 0;
    this.stopReason = null;
    this.consecutive5xx = 0;
  }

  assertAllowed(hostname) {
    const host = String(hostname || '').toLowerCase();
    if (!host) throw new ScopeError('empty hostname');
    if (!this.allowPrivateHosts && isPrivateHost(host)) {
      throw new ScopeError(`private/reserved host not allowed: ${host}`);
    }
    if (this.allowlist.size && !this.allowlist.has(host)) {
      throw new ScopeError(`host not in authorization allowlist: ${host}`);
    }
    return host;
  }

  async throttle() {
    const now = Date.now();
    const wait = Math.max(0, this.lastRequestAt + this.intervalMs - now);
    if (wait > 0) await new Promise(resolve => setTimeout(resolve, wait));
    this.lastRequestAt = Date.now();
  }

  #consume() {
    if (this.remaining <= 0) throw new BudgetExceededError('request budget exhausted');
    this.remaining -= 1;
    this.requestCount += 1;
  }

  #observeStatus(status) {
    if (status === 429) {
      this.stopReason = 'rate-limited';
      throw new StopConditionError('rate-limited (HTTP 429)');
    }
    if (status >= 500) {
      this.consecutive5xx += 1;
      if (this.consecutive5xx >= 2) {
        this.stopReason = 'service-unstable';
        throw new StopConditionError('service unstable (repeated 5xx)');
      }
    } else {
      this.consecutive5xx = 0;
    }
  }

  // Perform a single read-only HTTP request. `method` must be GET or HEAD.
  async request({ url, method = 'GET', headers = {} }) {
    const methodUpper = String(method).toUpperCase();
    if (methodUpper !== 'GET' && methodUpper !== 'HEAD') {
      throw new ScopeError(`method not allowed: ${methodUpper} (GET/HEAD only)`);
    }
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new ScopeError(`scheme not allowed: ${parsed.protocol}`);
    }
    this.assertAllowed(parsed.hostname);
    this.#consume();
    await this.throttle();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await fetch(parsed, {
        method: methodUpper,
        redirect: 'manual',
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      if (error.name === 'AbortError') throw new Error(`request timed out after ${this.timeoutMs}ms`);
      throw error;
    } finally {
      clearTimeout(timer);
    }

    this.#observeStatus(response.status);
    const location = response.headers.get('location');
    if (location) {
      let redirectHost;
      try { redirectHost = new URL(location, parsed).hostname; } catch { redirectHost = null; }
      if (redirectHost && !this.allowlist.has(redirectHost.toLowerCase())) {
        this.stopReason = 'redirect-off-allowlist';
        throw new StopConditionError(`redirect off allowlist: ${location}`);
      }
    }

    const body = methodUpper === 'HEAD' ? '' : await safeBody(response);
    return {
      status: response.status,
      headers: headersToObject(response.headers),
      contentType: response.headers.get('content-type') ?? null,
      body: body.slice(0, 16_000),
      truncated: body.length > 16_000,
      location: location ?? null,
    };
  }

  // DNS lookups (read-only, no allowlist enforcement beyond private-host guard).
  async dns(hostname, types = ['A', 'AAAA', 'MX', 'TXT', 'CAA', 'NS']) {
    this.assertAllowed(hostname);
    const out = {};
    for (const type of types) {
      try {
        switch (type) {
          case 'A': out.A = await lookup(hostname, { family: 4 }); break;
          case 'AAAA': out.AAAA = await lookup(hostname, { family: 6 }); break;
          case 'MX': out.MX = await resolveMx(hostname); break;
          case 'TXT': out.TXT = await resolveTxt(hostname); break;
          case 'CAA': out.CAA = await resolveCaa(hostname); break;
          case 'NS': out.NS = await resolveAny(hostname); break;
        }
      } catch { out[type] = null; }
    }
    return out;
  }

  // TLS certificate metadata via a handshake (no HTTP request consumed).
  async tls(hostname, port = 443) {
    this.assertAllowed(hostname);
    return new Promise((resolve, reject) => {
      const socket = connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: this.timeoutMs });
      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve({
          issuer: cert.issuer?.CN ?? null,
          subject: cert.subject?.CN ?? null,
          validFrom: cert.valid_from ?? null,
          validTo: cert.valid_to ?? null,
          protocol: socket.getProtocol(),
          authorized: socket.authorized,
        });
      });
      socket.once('error', error => { socket.destroy(); reject(error); });
      socket.once('timeout', () => { socket.destroy(); reject(new Error('TLS handshake timed out')); });
    });
  }
}

function headersToObject(headers) {
  const out = {};
  for (const [key, value] of headers.entries()) out[key] = value;
  return out;
}

async function safeBody(response) {
  try { return await response.text(); } catch { return ''; }
}

// Guard against SSRF and accidental probing of internal/loopback addresses.
export function isPrivateHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return true;
  if (host === '0.0.0.0' || host === '::' || host === '::1') return true;
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 0 || a >= 224) return true;
  }
  return false;
}

export function parseAllowlist(raw) {
  return String(raw ?? '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
}
