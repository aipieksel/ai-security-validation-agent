import test from 'node:test';
import assert from 'node:assert/strict';
import { checkEndpoints, checkHeaders, checkDns, checkCors, checkSupabaseTable, interpretSupabase } from '../lib/checks.mjs';
import { checkSecurityHeaders, fingerprint } from '../lib/fingerprints.mjs';

test('checkEndpoints ignores SPA catch-all 200 responses', () => {
  const results = [
    { path: '/api/v1', status: 200, contentType: 'text/html', body: '<!doctype html><html><body>'.padEnd(600, 'x') },
    { path: '/.env', status: 200, contentType: 'text/plain', body: 'SECRET_KEY=abc' },
    { path: '/robots.txt', status: 404, body: '' },
  ];
  const { findings, samples } = checkEndpoints(results, { asset: 'example.com' });
  // The SPA shell is not flagged; the real .env response is.
  assert.equal(samples.length, 1);
  assert.equal(samples[0].path, '/.env');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, 'Sensitive path exposed: /.env');
});

test('checkHeaders emits a finding per missing header', () => {
  const findings = checkHeaders(checkSecurityHeaders({}), { asset: 'example.com' });
  assert.ok(findings.length >= 3);
  assert.ok(findings.some(f => f.title.includes('Strict-Transport-Security')));
  assert.ok(findings.some(f => f.title.includes('Content-Security-Policy')));
});

test('checkDns detects missing SPF/DMARC/CAA', () => {
  const findings = checkDns({ TXT: [], CAA: null }, { asset: 'example.com' });
  assert.ok(findings.some(f => f.title === 'Missing SPF record'));
  assert.ok(findings.some(f => f.title === 'Missing DMARC record'));
  assert.ok(findings.some(f => f.title === 'Missing CAA record'));
});

test('checkDns accepts present SPF and DMARC', () => {
  const findings = checkDns({ TXT: [['v=spf1 ~all', 'v=DMARC1; p=none']], CAA: [{ tag: 'issue', value: 'letsencrypt.org' }] }, { asset: 'example.com' });
  assert.equal(findings.length, 0);
});

test('checkCors flags wildcard origin', () => {
  const findings = checkCors([{ origin: '*', allowOrigin: '*' }], { asset: 'example.com' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'HIGH');
});

test('interpretSupabase treats permission denied and missing function as protective', () => {
  assert.equal(interpretSupabase({ status: 401, body: '' }).protective, true);
  assert.equal(interpretSupabase({ status: 200, body: '{"code":"42501","message":"permission denied"}' }).protective, true);
  assert.equal(interpretSupabase({ status: 200, body: '{"code":"PGRST202"}' }).protective, true);
  assert.equal(interpretSupabase({ status: 200, body: '[{"id":1}]' }).protective, false);
});

test('checkSupabaseTable flags only real data exposure', () => {
  const leak = checkSupabaseTable({ table: 'profiles', status: 200, body: '[{"id":1}]' }, { asset: 'example.com' });
  assert.equal(leak.severity, 'CRITICAL');
  const safe = checkSupabaseTable({ table: 'profiles', status: 200, body: '{"code":"42501"}' }, { asset: 'example.com' });
  assert.equal(safe, null);
});

test('fingerprint detects Cloudflare and Supabase markers', () => {
  const matches = fingerprint({ headers: { 'cf-ray': 'abc' }, body: 'sb_publishable_xyz rest/v1' });
  const ids = matches.map(m => m.id);
  assert.ok(ids.includes('cloudflare'));
  assert.ok(ids.includes('supabase'));
});
