# TBackend — GHAS Test Backend

**This repository is intentionally vulnerable.** It exists solely to test [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) features including CodeQL, Dependabot, and secret scanning (Gitleaks).

Do **not** deploy this code. Do **not** use the fake secrets in production — they follow real credential patterns for scanner testing only.

## Stack

- **Node.js 18+** with **Express 4.x**
- SQLite-style query simulation (no real database required)

## Quick start

```bash
npm install
npm start
```

Server runs on `http://localhost:3000`.

## API endpoints (all intentionally unsafe)

| Endpoint | Vulnerability |
|----------|---------------|
| `GET /api/users/:id` | SQL injection |
| `POST /api/users/search` | SQL injection |
| `GET /api/ping?host=` | Command injection |
| `POST /api/run` | Command injection |
| `GET /api/file?path=` | Path traversal |
| `GET /api/download?name=` | Path traversal |
| `GET /api/greet?name=` | Reflected XSS |
| `POST /api/deserialize` | Unsafe deserialization (eval) |
| `POST /api/register` | Weak crypto (MD5, Math.random) |
| `POST /api/merge-config` | Prototype pollution (lodash) |

## Intentional findings by GHAS tool

### CodeQL (source code)

- SQL injection via string concatenation in queries
- Command injection via `child_process.exec` with user input
- Path traversal via `fs.readFileSync` with user paths
- Reflected XSS in HTML responses
- Unsafe deserialization using `eval()`
- Weak cryptography (MD5 hashing, `Math.random()` for tokens)

### Dependabot / dependency review

Pinned vulnerable dependency versions in `package.json`:

| Package | Version | Known issue |
|---------|---------|-------------|
| `lodash` | 4.17.15 | CVE-2021-23337 (command injection) |
| `minimist` | 1.2.5 | CVE-2021-44906 (prototype pollution, critical) |
| `serialize-javascript` | 3.1.0 | CVE-2020-7660 (RCE, critical) |
| `axios` | 0.21.1 | CVE-2021-3749 (SSRF) |
| `jsonwebtoken` | 8.5.1 | CVE-2022-23529 |
| `express` | 4.17.1 | Outdated release |

### Gitleaks / secret scanning

Fake credentials in:

- `.env.example` — AWS keys, GitHub PAT, DB password, Slack webhook
- `config/secrets.json` — structured fake secrets
- `config/index.js` — hardcoded API keys and tokens

## GitHub Actions workflows

| Workflow | Trigger | Failure condition |
|----------|---------|-------------------|
| `.github/workflows/codeql.yml` | PR/push to main | Critical CodeQL findings (security-severity > 9.0) via SARIF post-check |
| `.github/workflows/dependency-review.yml` | PR to main | Critical dependency changes (`dependency-review-action`) + `npm audit --audit-level=critical` |
| `.github/workflows/gitleaks.yml` | PR/push to main | Any detected secret patterns |

## Dependabot

`.github/dependabot.yml` opens weekly PRs for npm and GitHub Actions updates.

## License

For internal security testing only.
