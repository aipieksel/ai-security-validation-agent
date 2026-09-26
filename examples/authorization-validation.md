# Authorized Validation Scope

Target owner: [name / organization]

Assessment window: [UTC start] to [UTC end]

Allowed hostnames:
- `example.invalid`

Allowed methods:
- DNS lookups
- TLS certificate metadata
- HTTP HEAD
- HTTP GET for these public paths only: `/`, `/robots.txt`, `/sitemap.xml`

Request budget: 30 total requests, at least 1 second apart

Stop conditions:
- Any 429 response
- Two consecutive 5xx responses
- Redirect outside the allowlist
- Service instability or an unclear authorization boundary

Data handling:
- Do not submit credentials or form data.
- Redact tokens, cookies, emails, and personal data.
- Store only minimal response evidence.
