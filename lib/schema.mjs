// Reusable schema for the artifacts exchanged between the reconnaissance
// preset and the validation companion. Kept dependency-free so both sides can
// read and write it without importing each other's code.

export const SCHEMA_VERSION = '1.0.0';

export function emptyFindingsDoc({ target = null, generatedAt = new Date().toISOString() } = {}) {
  return {
    schemaVersion: SCHEMA_VERSION,
    target,
    generatedAt,
    findings: [],
    summary: { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  };
}

export function validateFindingsDoc(doc) {
  if (!doc || typeof doc !== 'object') throw new Error('findings document must be an object');
  if (!Array.isArray(doc.findings)) throw new Error('findings document must contain a findings array');
  for (const finding of doc.findings) {
    if (!finding || typeof finding !== 'object') throw new Error('each finding must be an object');
    if (!finding.title) throw new Error('each finding requires a title');
  }
  return doc;
}
