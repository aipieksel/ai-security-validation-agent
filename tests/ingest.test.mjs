import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ingest } from '../lib/ingest.mjs';
import { markdownReport, htmlReport, jsonReport } from '../lib/report.mjs';
import { validate } from '../lib/validate.mjs';

test('ingest extracts header findings and secrets from a report', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ingest-'));
  try {
    await writeFile(join(dir, 'RECON_REPORT.md'), [
      '# Recon',
      'Target: example.com',
      'Content-Security-Policy: Missing',
      'X-Frame-Options: Missing',
      'Strict-Transport-Security: max-age=31536000',
      'Exposed key: sb_publishable_abc123def456',
    ].join('\n'));
    const doc = await ingest({ dir, target: 'example.com' });
    assert.ok(doc.findings.some(f => f.title.includes('Content-Security-Policy')));
    assert.ok(doc.findings.some(f => f.title.includes('X-Frame-Options')));
    assert.ok(doc.findings.some(f => f.category === 'secrets'));
    assert.ok(doc.assets.hosts.includes('example.com'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ingest tolerates a missing report', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ingest-empty-'));
  try {
    const doc = await ingest({ dir, target: 'example.com' });
    assert.equal(doc.findings.length, 0);
    assert.equal(doc.summary.total, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('report emitters produce valid output', () => {
  const doc = {
    schemaVersion: '1.0.0', target: 'example.com', generatedAt: 'now',
    findings: [], summary: { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  };
  assert.ok(markdownReport(doc).includes('Security Validation Report'));
  assert.ok(htmlReport(doc).includes('<!DOCTYPE html>'));
  assert.deepEqual(JSON.parse(jsonReport(doc)).target, 'example.com');
});

test('validate runs local-only analysis without a target', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'validate-'));
  try {
    await writeFile(join(dir, 'RECON_REPORT.md'), 'Content-Security-Policy: Missing\n');
    const doc = await validate({ dir, runNetwork: false });
    assert.ok(doc.findings.some(f => f.title.includes('Content-Security-Policy')));
    assert.ok(doc.coverageGaps.some(g => g.includes('No authorized host')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
