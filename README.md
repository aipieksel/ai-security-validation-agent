# AI Security Validation Agent

Maintained by [aipieksel](https://github.com/aipieksel). Upstream credits and licenses remain with their respective authors.

A controlled, evidence-driven **security validation** companion to the AI Security Reconnaissance Agent. It consumes reconnaissance reports and turns their observations into prioritized, reproducible remediation work.

It does **not** exploit live systems and does not ship exploit payloads. It runs a deterministic engine that performs local report analysis and, only when an authorization file explicitly permits it, bounded read-only checks such as DNS, TLS metadata, response headers, named public GET/HEAD resources, and optional **authorized confirmation** of those findings (cookie flags, redirect stay-on-allowlist, and GET re-checks of previously observed paths).

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

The preset in `presets/ai-security-validation-agent/` tells a DeepSeek Harness session to drive the same engine through its Bash tool. Copy the preset into `$DSH_HOME/.agent-presets/ai-security-validation-agent/`, select it, and give it a mission workspace containing `RECON_REPORT.md` and an `AUTHORIZATION.md`.

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

## Correctness fixes over the historical scanner

1. A single-page app's catch-all route (every path returns the same `index.html` with HTTP 200) is **not** treated as an exposed endpoint.
2. Supabase `permission denied` (42501) and `function not found` (PGRST202) responses are recognized as protective outcomes, not data leaks.

## Explicitly prohibited

Credential guessing, brute force, authentication or reset attempts, injection or traversal payloads, WAF bypasses, uploads, writes, deletes, private-data retrieval, or requests using secrets.

## License

[MIT](LICENSE).
