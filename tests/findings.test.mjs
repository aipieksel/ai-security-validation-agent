import test from 'node:test';
import assert from 'node:assert/strict';
import { createFinding, dedupeFindings, sortFindings, summarize, severityFromCvss, normalizeSeverity } from '../lib/findings.mjs';

test('severityFromCvss maps score bands', () => {
  assert.equal(severityFromCvss(9.5), 'CRITICAL');
  assert.equal(severityFromCvss(8.0), 'HIGH');
  assert.equal(severityFromCvss(5.0), 'MEDIUM');
  assert.equal(severityFromCvss(2.0), 'LOW');
  assert.equal(severityFromCvss(0.0), 'INFO');
});

test('normalizeSeverity and normalizeConfidence coerce inputs', () => {
  assert.equal(normalizeSeverity('critical'), 'CRITICAL');
  assert.equal(normalizeSeverity('bogus'), 'INFO');
});

test('createFinding applies category default CVSS and severity', () => {
  const f = createFinding({ title: 'Missing SPF', category: 'email', confidence: 'confirmed' });
  assert.equal(f.cvss, 7.5);
  assert.equal(f.severity, 'HIGH');
  assert.deepEqual(f.evidence, []);
});

test('dedupeFindings merges evidence and keeps stronger confidence/severity', () => {
  const a = createFinding({ id: 'a', title: 'X', asset: 'h', severity: 'MEDIUM', cvss: 5, confidence: 'possible', evidence: ['1'] });
  const b = createFinding({ id: 'b', title: 'X', asset: 'h', severity: 'HIGH', cvss: 8, confidence: 'confirmed', evidence: ['2'] });
  const [merged] = dedupeFindings([a, b]);
  assert.equal(merged.severity, 'HIGH');
  assert.equal(merged.confidence, 'confirmed');
  assert.deepEqual(merged.evidence.sort(), ['1', '2']);
});

test('sortFindings orders by severity then confidence then cvss', () => {
  const low = createFinding({ title: 'low', severity: 'LOW', cvss: 1, confidence: 'unverified' });
  const crit = createFinding({ title: 'crit', severity: 'CRITICAL', cvss: 9, confidence: 'confirmed' });
  const high = createFinding({ title: 'high', severity: 'HIGH', cvss: 7, confidence: 'probable' });
  assert.deepEqual(sortFindings([low, high, crit]).map(f => f.title), ['crit', 'high', 'low']);
});

test('summarize counts by severity', () => {
  const findings = [
    createFinding({ title: 'a', severity: 'CRITICAL', cvss: 9 }),
    createFinding({ title: 'b', severity: 'CRITICAL', cvss: 9 }),
    createFinding({ title: 'c', severity: 'LOW', cvss: 2 }),
  ];
  const summary = summarize(findings);
  assert.equal(summary.total, 3);
  assert.equal(summary.CRITICAL, 2);
  assert.equal(summary.LOW, 1);
  assert.equal(summary.HIGH, 0);
});
