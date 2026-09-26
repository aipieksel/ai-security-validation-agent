#!/usr/bin/env node
// CLI entry point for the validation engine. Ingest a reconnaissance report
// and, when authorized, run enforced read-only checks and emit reports.

import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { validate, jsonReport, markdownReport, htmlReport } from '../lib/validate.mjs';
import { parseAllowlist } from '../lib/probe.mjs';

function usage() {
  return `Usage: node scripts/validate.mjs --dir <workspace> [options]

Options:
  --target <host>        Primary hostname (also added to the allowlist)
  --allowlist <hosts>    Comma/space-separated authorized hostnames
  --budget <n>           Maximum requests (default 30)
  --interval-ms <n>      Minimum ms between requests (default 1000)
  --timeout-ms <n>       Request timeout in ms (default 5000)
  --no-network           Skip all network checks (local analysis only)
  --confirm              Re-check findings with authorized GET/HEAD proofs
  --out <dir>            Output directory for reports (default: workspace)

Writes VALIDATION_REPORT.md, findings.json, and report.html.
`;
}

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i === -1 || i + 1 >= args.length ? null : args[i + 1];
};

if (args.includes('--help') || !args.includes('--dir')) {
  console.log(usage());
  process.exit(args.includes('--help') ? 0 : 1);
}

const dir = resolve(opt('--dir'));
const target = opt('--target');
const allowlist = parseAllowlist(opt('--allowlist') ?? '');
const budget = opt('--budget') ? Number(opt('--budget')) : 30;
const intervalMs = opt('--interval-ms') ? Number(opt('--interval-ms')) : 1000;
const timeoutMs = opt('--timeout-ms') ? Number(opt('--timeout-ms')) : 5000;
const runNetwork = !args.includes('--no-network');
const confirm = args.includes('--confirm');
const outDir = resolve(opt('--out') ?? dir);

if (target && !allowlist.includes(target)) allowlist.push(target);

const doc = await validate({ dir, target, allowlist, budget, intervalMs, timeoutMs, runNetwork, confirm });
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, 'findings.json'), jsonReport(doc));
await writeFile(join(outDir, 'VALIDATION_REPORT.md'), markdownReport(doc));
await writeFile(join(outDir, 'report.html'), htmlReport(doc));

console.log(`Validated ${doc.target ?? '(local analysis only)'}`);
console.log(`Findings: ${doc.summary.total} (CRITICAL ${doc.summary.CRITICAL}, HIGH ${doc.summary.HIGH}, MEDIUM ${doc.summary.MEDIUM}, LOW ${doc.summary.LOW}, INFO ${doc.summary.INFO})`);
if (doc.requestCount != null) console.log(`Requests: ${doc.requestCount}`);
if (doc.stopReason) console.log(`Stop reason: ${doc.stopReason}`);
for (const gap of doc.coverageGaps ?? []) console.log(`Gap: ${gap}`);
console.log(`Reports written to ${outDir}`);
