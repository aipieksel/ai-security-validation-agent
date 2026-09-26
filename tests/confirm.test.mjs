import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { Probe, ScopeError } from '../lib/probe.mjs';
import {
  pathFromFinding,
  confirmationStatus,
  inspectCookieFlags,
  redirectStaysOnAllowlist,
  confirmAuthorized,
} from '../lib/confirm.mjs';

test('pathFromFinding reads evidence paths and title paths', () => {
  assert.equal(pathFromFinding({ evidence: ['/.env'] }), '/.env');
  assert.equal(pathFromFinding({ evidence: ['headers:Content-Security-Policy'] }), null);
  assert.equal(pathFromFinding({ title: 'Sensitive path exposed: /admin', evidence: [] }), '/admin');
});

test('confirmationStatus maps HTTP outcomes without payloads', () => {
  assert.equal(confirmationStatus({ actualStatus: 200 }), 'confirmed');
  assert.equal(confirmationStatus({ actualStatus: 404 }), 'not-reproduced');
  assert.equal(confirmationStatus({ actualStatus: 500 }), 'inconclusive');
  assert.equal(confirmationStatus({ error: 'timeout' }), 'inconclusive');
});

test('inspectCookieFlags flags missing HttpOnly, Secure and SameSite', () => {
  const findings = inspectCookieFlags({
    'set-cookie': ['session=abc; Path=/'],
  }, { asset: 'example.com' });
  assert.equal(findings.length, 3);
  assert.ok(findings.some((item) => item.title.includes('HttpOnly')));
  assert.ok(findings.some((item) => item.title.includes('Secure')));
  assert.ok(findings.some((item) => item.title.includes('SameSite')));
});

test('redirectStaysOnAllowlist rejects off-allowlist Location hosts', () => {
  const ok = redirectStaysOnAllowlist({ location: 'https://example.com/app' }, ['example.com']);
  assert.equal(ok.allowed, true);
  const bad = redirectStaysOnAllowlist({ location: 'https://evil.example/phish' }, ['example.com']);
  assert.equal(bad.allowed, false);
});

test('confirmAuthorized re-checks findings on a local fixture and stays GET/HEAD-only', async () => {
  const server = createServer((req, res) => {
    if (req.method === 'HEAD' && req.url === '/') {
      res.writeHead(200, { 'set-cookie': 'session=abc; Path=/' });
      return res.end();
    }
    if (req.url === '/.env') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('SECRET_KEY=example');
    }
    res.writeHead(404);
    res.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  const probe = new Probe({ allowlist: ['127.0.0.1'], allowPrivateHosts: true, intervalMs: 0, budget: 20 });
  try {
    await assert.rejects(
      () => probe.request({ url: `http://127.0.0.1:${port}/`, method: 'POST' }),
      ScopeError,
    );
    const result = await confirmAuthorized({
      probe,
      host: '127.0.0.1',
      port,
      scheme: 'http',
      findings: [
        { id: 'Fenv', title: 'Sensitive path exposed: /.env', evidence: ['/.env'], confidence: 'confirmed' },
        { id: 'Fmissing', title: 'Publicly accessible path: /gone', evidence: ['/gone'], confidence: 'probable' },
      ],
    });
    assert.ok(result.extraFindings.some((item) => item.title.includes('HttpOnly')));
    const env = result.confirmations.find((item) => item.findingId === 'Fenv');
    const gone = result.confirmations.find((item) => item.findingId === 'Fmissing');
    assert.equal(env.status, 'confirmed');
    assert.equal(gone.status, 'not-reproduced');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
