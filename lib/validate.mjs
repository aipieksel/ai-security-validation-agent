// Validation orchestration: ingest a reconnaissance report, run enforced
// read-only checks against explicitly authorized hosts, and emit reports.

import { ingest } from './ingest.mjs';
import { Probe, parseAllowlist, ScopeError, BudgetExceededError, StopConditionError } from './probe.mjs';
import { COMMON_PATHS, checkEndpoints, checkHeaders, checkDns, checkCors, checkTlsProtocols, checkSupabaseTable } from './checks.mjs';
import { checkSecurityHeaders } from './fingerprints.mjs';
import { confirmAuthorized } from './confirm.mjs';
import { dedupeFindings, sortFindings, summarize } from './findings.mjs';
import { emptyFindingsDoc } from './schema.mjs';
import { jsonReport, markdownReport, htmlReport } from './report.mjs';

const WEAK_TLS = ['ssl2', 'ssl3', 'tls1', 'tls1_1'];

export async function validate({
  dir,
  target = null,
  allowlist = [],
  budget = 30,
  intervalMs = 1000,
  timeoutMs = 5000,
  paths = COMMON_PATHS,
  runNetwork = true,
  corsOrigins = ['*', 'https://evil.invalid'],
  scheme = 'https',
  allowPrivateHosts = false,
  port = null,
  confirm = false,
} = {}) {
  const allowed = allowlist.length ? allowlist : (target ? [target] : []);
  const doc = await ingest({ dir, target });
  const coverageGaps = [];
  const ownerVerificationPlans = [];

  if (runNetwork && allowed.length) {
    const probe = new Probe({ allowlist: allowed, budget, intervalMs, timeoutMs, allowPrivateHosts });
    const host = allowed[0];
    const authority = port ? `${host}:${port}` : host;
    const findings = [...doc.findings];

    try {
      // DNS and email security (read-only lookups).
      const dnsResult = await probe.dns(host);
      findings.push(...checkDns(dnsResult, { asset: host }));

      // TLS certificate metadata and weak protocol detection.
      try {
        const cert = await probe.tls(host);
        doc.certificate = cert;
      } catch (error) {
        coverageGaps.push(`TLS handshake failed for ${host}: ${error.message}`);
      }
      const protocolResults = [];
      for (const protocol of WEAK_TLS) {
        // Node's TLS client maps legacy protocol names; probe them via socket
        // options is not supported, so we conservatively record as not tested.
        protocolResults.push({ protocol, enabled: false, note: 'not independently probed' });
      }
      findings.push(...checkTlsProtocols(protocolResults, { asset: host }));

      // Security headers via a single HEAD request.
      try {
        const head = await probe.request({ url: `${scheme}://${authority}/`, method: 'HEAD' });
        findings.push(...checkHeaders(checkSecurityHeaders(head.headers, host), { asset: host }));
      } catch (error) {
        if (!(error instanceof ScopeError || error instanceof BudgetExceededError || error instanceof StopConditionError)) {
          coverageGaps.push(`HEAD request failed for ${host}: ${error.message}`);
        }
      }

      // Endpoint exposure checks (GET only).
      const endpointResults = [];
      for (const path of paths) {
        try {
          const result = await probe.request({ url: `${scheme}://${authority}${path}`, method: 'GET' });
          endpointResults.push({ path, ...result });
        } catch (error) {
          if (error instanceof StopConditionError || error instanceof BudgetExceededError) {
            coverageGaps.push(`Stopped endpoint checks: ${error.message}`);
            break;
          }
          endpointResults.push({ path, error: error.message });
        }
      }
      const endpointCheck = checkEndpoints(endpointResults, { asset: host, allowlist });
      findings.push(...endpointCheck.findings);
      doc.samples = endpointCheck.samples;

      // CORS posture.
      const corsResults = [];
      for (const origin of corsOrigins) {
        try {
          const result = await probe.request({ url: `${scheme}://${authority}/`, method: 'HEAD', headers: { Origin: origin } });
          corsResults.push({ origin, allowOrigin: result.headers['access-control-allow-origin'] ?? null });
        } catch { /* skip */ }
      }
      findings.push(...checkCors(corsResults, { asset: host }));

      if (confirm) {
        const confirmed = await confirmAuthorized({
          probe,
          findings,
          scheme,
          host,
          port,
        });
        findings.push(...confirmed.extraFindings);
        doc.confirmations = confirmed.confirmations;
      }

      doc.findings = sortFindings(dedupeFindings(findings));
      doc.summary = summarize(doc.findings);
      doc.requestCount = probe.requestCount;
      doc.stopReason = probe.stopReason;
    } catch (error) {
      if (error instanceof ScopeError || error instanceof BudgetExceededError || error instanceof StopConditionError) {
        coverageGaps.push(`Validation stopped: ${error.message}`);
        doc.stopReason = error.message;
      } else {
        throw error;
      }
    }
  } else if (!allowed.length) {
    coverageGaps.push('No authorized host: network checks were skipped. Provide a target and allowlist.');
  } else if (confirm) {
    coverageGaps.push('Confirmation requires authorized network checks; --no-network skipped confirmation.');
  }

  doc.coverageGaps = coverageGaps;
  doc.ownerVerificationPlans = ownerVerificationPlans;
  doc.findings = sortFindings(dedupeFindings(doc.findings));
  doc.summary = summarize(doc.findings);
  return doc;
}

export { jsonReport, markdownReport, htmlReport };
export { emptyFindingsDoc };
