# AI Security Validation Agent

Maintained by [aipieksel](https://github.com/aipieksel). Upstream credits and licenses remain with their respective authors.

AI Security Validation Agent turns a reconnaissance report into a prioritized set of findings that an owner can inspect and remediate. It ingests the report and local artifacts, normalizes evidence, checks for common false positives, and produces Markdown, JSON, and HTML reports.

Local analysis needs no model or network access. For a host you are authorized to assess, supply the target and allowlist flags to enable a bounded set of read-only DNS, TLS, header, and public GET/HEAD checks. Optional confirmation rechecks previously observed paths and response details. The engine enforces host and method limits in code; the [reconnaissance agent](https://github.com/aipieksel/ai-security-reconnaissance-agent) can supply its input, but is not required to run the CLI.

## From report to remediation

1. Put `RECON_REPORT.md` and any supporting `artifacts/` in a mission directory.
2. Run local analysis first; add an authorized network pass only for an in-scope host.
3. Review `VALIDATION_REPORT.md`, `findings.json`, and `report.html`, including their evidence and remediation guidance.

## Run without the Harness

The engine is a plain CLI. No Harness or model is required.

```sh
# Local analysis only — ingest a report and produce findings (no network)
node scripts/validate.mjs --dir ./mission --no-network

# Authorized network pass — bounded read-only checks against a host you own
node scripts/validate.mjs --dir ./mission \
  --target example.com \
  --allowlist example.com \
  --budget 30

# Same pass, plus authorized confirmation of findings (still GET/HEAD only)
node scripts/validate.mjs --dir ./mission \
  --target example.com \
  --allowlist example.com \
  --budget 30 \
  --confirm
```

Both modes write `VALIDATION_REPORT.md`, `findings.json`, and `report.html` into the target directory.

## Run with the Harness

The preset in `presets/ai-security-validation-agent/` tells a DeepSeek Harness session to drive the same engine through its Bash tool. Copy the preset into `$DSH_HOME/.agent-presets/ai-security-validation-agent/`, select it, and give it a mission workspace containing `RECON_REPORT.md` and an `AUTHORIZATION.md`. The standalone CLI uses its explicit flags; it does not parse that authorization file.

## How it works

| Module | Purpose |
| --- | --- |
| `lib/findings.mjs` | Normalized finding model (severity, CVSS, confidence, evidence, remediation), deduplication, sorting |
| `lib/fingerprints.mjs` | Technology fingerprints and the security-header policy |
| `lib/ingest.mjs` | Parses `RECON_REPORT.md` and `artifacts/` into structured findings |
| `lib/probe.mjs` | Enforced read-only network probe: GET/HEAD only, host allowlist, request budget, throttling, SSRF guard, stop conditions |
| `lib/confirm.mjs` | Authorized confirmation: cookie flags, redirect allowlist, GET re-checks of finding paths |
| `lib/checks.mjs` | Deterministic checks (headers, DNS/email, endpoint exposure, CORS, TLS, Supabase RLS) |
| `lib/validate.mjs` | Orchestration |
| `lib/report.mjs` | JSON, Markdown, and HTML emitters |
| `scripts/validate.mjs` | CLI entry point |

## Safety is enforced in code, not a prompt

The probe hard-blocks non-GET/HEAD methods, enforces the host allowlist and request budget, throttles requests, guards against private/loopback targets (SSRF), and stops on 429, repeated 5xx, or redirects off the allowlist.

## How findings avoid common false positives

1. A single-page app's catch-all route (every path returns the same `index.html` with HTTP 200) is **not** treated as an exposed endpoint.
2. Supabase `permission denied` (42501) and `function not found` (PGRST202) responses are treated as protective outcomes, not data leaks.

## Explicitly prohibited

Credential guessing, brute force, authentication or reset attempts, injection or traversal payloads, WAF bypasses, uploads, writes, deletes, private-data retrieval, or requests using secrets.

## License

[MIT](LICENSE).
