import test from 'node:test';
import assert from 'node:assert/strict';
import { Probe, isPrivateHost, parseAllowlist, ScopeError, StopConditionError, BudgetExceededError } from '../lib/probe.mjs';

test('isPrivateHost detects loopback and private ranges', () => {
  assert.equal(isPrivateHost('localhost'), true);
  assert.equal(isPrivateHost('127.0.0.1'), true);
  assert.equal(isPrivateHost('10.1.2.3'), true);
  assert.equal(isPrivateHost('192.168.1.1'), true);
  assert.equal(isPrivateHost('172.16.0.1'), true);
  assert.equal(isPrivateHost('169.254.1.1'), true);
  assert.equal(isPrivateHost('example.com'), false);
  assert.equal(isPrivateHost('8.8.8.8'), false);
});

test('parseAllowlist splits commas and whitespace', () => {
  assert.deepEqual(parseAllowlist('a.com, b.com\nc.com'), ['a.com', 'b.com', 'c.com']);
});

test('Probe rejects non-GET/HEAD methods', async () => {
  const probe = new Probe({ allowlist: ['example.com'] });
  await assert.rejects(() => probe.request({ url: 'https://example.com/', method: 'POST' }), ScopeError);
  await assert.rejects(() => probe.request({ url: 'https://example.com/', method: 'DELETE' }), ScopeError);
});

test('Probe rejects hosts outside the allowlist', async () => {
  const probe = new Probe({ allowlist: ['example.com'] });
  await assert.rejects(() => probe.request({ url: 'https://evil.com/' }), ScopeError);
});

test('Probe rejects private hosts by default', async () => {
  const probe = new Probe({ allowlist: [] });
  await assert.rejects(() => probe.request({ url: 'http://127.0.0.1/' }), ScopeError);
});

test('Probe enforces the request budget', async () => {
  const probe = new Probe({ allowlist: ['example.com'], budget: 1, intervalMs: 0 });
  // Consume the single allowed request without hitting the network by using a
  // private host? No — use the DNS path which is budget-free, then a request.
  // Instead, directly exhaust the budget counter.
  probe.remaining = 0;
  await assert.rejects(() => probe.request({ url: 'https://example.com/' }), BudgetExceededError);
});

test('Probe stops on 429 via a local fixture', async () => {
  const { createServer } = await import('node:http');
  const server = createServer((req, res) => { res.writeHead(429); res.end(); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const probe = new Probe({ allowlist: ['127.0.0.1'], allowPrivateHosts: true, intervalMs: 0 });
  await assert.rejects(() => probe.request({ url: `http://127.0.0.1:${port}/` }), StopConditionError);
  assert.equal(probe.stopReason, 'rate-limited');
  await new Promise(resolve => server.close(resolve));
});
