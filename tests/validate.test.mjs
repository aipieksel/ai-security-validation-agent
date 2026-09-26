import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { validate } from '../lib/validate.mjs';

// End-to-end: a local fixture serves a report-derived target; the engine runs
// enforced GET/HEAD checks against it and emits findings. No external host is
// ever contacted, and the allowlist is limited to the loopback fixture.
test('validate performs bounded read-only checks against a local fixture', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'validate-e2e-'));
  const fixture = createServer((req, res) => {
    if (req.method === 'HEAD' && req.url === '/') {
      res.writeHead(200, { 'content-type': 'text/html' }); // missing security headers
      return res.end();
    }
    if (req.url === '/.env') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('SECRET_KEY=topsecret');
    }
    if (req.url === '/robots.txt') {
      res.writeHead(404);
      return res.end();
    }
    // SPA catch-all for everything else.
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><html><body>' + 'x'.repeat(600) + '</body></html>');
  });
  fixture.listen(0, '127.0.0.1');
  await once(fixture, 'listening');
  const port = fixture.address().port;
  const host = '127.0.0.1';

  try {
    await writeFile(join(dir, 'RECON_REPORT.md'), `Target: ${host}\nContent-Security-Policy: Missing\n`);
    const doc = await validate({
      dir,
      target: host,
      allowlist: [host],
      budget: 50,
      intervalMs: 0,
      timeoutMs: 2000,
      paths: ['/', '/.env', '/robots.txt', '/api/v1'],
      scheme: 'http',
      allowPrivateHosts: true,
      port,
    });

    // The .env path is a real (non-shell) response -> flagged HIGH exposure.
    assert.ok(doc.findings.some(f => f.title.includes('.env') && f.severity === 'HIGH'));
    // Missing CSP from the HEAD response -> flagged.
    assert.ok(doc.findings.some(f => f.title.includes('Content-Security-Policy')));
    // The SPA catch-all /api/v1 must NOT be flagged as exposed.
    assert.ok(!doc.findings.some(f => f.title.includes('/api/v1')));
    // Requests were actually issued.
    assert.ok(doc.requestCount > 0);
  } finally {
    await new Promise(resolve => fixture.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});
