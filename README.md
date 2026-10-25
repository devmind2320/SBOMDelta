# SBOMDelta

Git diff, but for your dependencies — and for the security consequences of changing them.

Most supply-chain tools answer *"what is vulnerable right now?"*. SBOMDelta answers a
different question:

> **What changed, and did that change make us less secure?**

It installs as a GitHub App. On every push to the default branch and on every pull
request it generates a [CycloneDX](https://cyclonedx.org/) SBOM for that exact commit,
compares it against the right baseline, and reports the difference back onto the commit
as a check run:

```
3 dependency changes

Added (1)
- npm express 4.18.2

Updated (1)
- npm axios 1.6.0 → 1.7.0

Removed (1)
- npm left-pad 1.3.0
```

Over time this builds a per-repository history of *dependency drift* rather than a
snapshot of current vulnerabilities.

---

## Status

Phases 1–3 and 6 are implemented and tested: GitHub App integration, SBOM generation
and archival, the diff engine, and the Vue dashboard.

| Phase | Scope | State |
|-------|-------------------------------------------------|-------------|
| 1 | GitHub App, webhooks, check runs | Done |
| 2 | Clone, syft/CycloneDX, blob archival | Done |
| 3 | Diff engine, drift history | Done |
| 6 | Vue dashboard | Done |
| 4 | OSV vulnerability + license + maintenance enrichment | Next |
| 5 | Risk scoring and policy thresholds | Planned |
| 7 | Crypto primitive analysis, contributor analytics | Planned |

The schema already carries the `vulnerabilities` table, the `scans.enriched_at` stamp
and the `risk_score` / `risk_delta` columns that Phases 4–5 fill in, so those phases add
code rather than migrations. The dashboard reads those fields today and renders an
explicit "not analyzed yet" state for them — deliberately distinct from "nothing found",
because an empty vulnerability table must never be mistaken for a clean bill of
health.

---

## How it works

```
GitHub ──push / pull_request──▶ Go API ──enqueue──▶ Postgres (jobs)
                                   │                    │
                                 202 Accepted      FOR UPDATE SKIP LOCKED
                                                        │
                                                        ▼
                                                    Go worker
                                                        │
                            ┌───────────────────────────┼───────────────────────┐
                            ▼                           ▼                       ▼
                    shallow git clone            syft → CycloneDX        archive to S3
                                                        │
                                                        ▼
                                                  DIFF ENGINE
                                       base SBOM ◀────┴────▶ head SBOM
                                                        │
                                        added · updated · removed · unchanged
                                                        │
                                    ┌───────────────────┴────────────────┐
                                    ▼                                    ▼
                             Postgres projection                  GitHub check run
                        (components, drift_events)                 on the commit
```

The webhook handler never scans anything. It verifies the signature, records just enough
to act on the event, enqueues a job, and returns `202` — a handler that cloned a
repository inline would hold GitHub's delivery open for minutes and time out.

### Choosing the baseline

The comparison is only as meaningful as what it compares against:

- **A pull request** is diffed against its **base commit**, so the check shows what the
  PR itself changes and nothing else.
- **A push** is diffed against the **previous tip of the default branch**.
- **The first scan** of a repository is a baseline, not a diff. Every component reported
  as "added" on day one would be noise. A repository the App can reach that has no
  default-branch scan yet gets an **initial scan** of its default branch head
  automatically, queued by repository reconciliation (on every worker start and after
  installation changes) and spaced out across repositories. Initial scans post no check
  run.

When a PR's base commit was never scanned (the app was installed mid-stream), the worker
backfills it before diffing, so the comparison is against the real base rather than
against nothing.

### Dependency identity

The diff matches on the **version-less PURL** (`pkg:npm/lodash`), not the full one. That
single decision is what makes `lodash 4.17.21 → 4.18.0` register as *one update* instead
of an unrelated add plus remove. Namespaces are preserved, so `@scope/utils` never
collides with `utils`, and qualifiers are stripped, so an architecture change does not
read as a different dependency.

Packages that ship several versions side by side — routine in npm trees — are handled
explicitly: unchanged versions stay unchanged, and the versions that moved are paired in
version order.

---

## Running it locally

### 1. Create a GitHub App

Under **Settings → Developer settings → GitHub Apps → New GitHub App**:

| Field | Value |
|---------------------|-------------------------------------------------|
| Webhook URL | your public tunnel, e.g. `https://<id>.ngrok.app/webhooks/github` |
| Webhook secret | any random string — you will need it below |
| Callback URL | your `PUBLIC_URL` plus `/api/auth/github/callback`, e.g. `http://localhost:5173/api/auth/github/callback` |
| Repository permissions | **Contents:** Read-only · **Pull requests:** Read-only · **Checks:** Read & write · **Metadata:** Read-only |
| Subscribe to events | **Push**, **Pull request** |

Generate a private key, and save it as `secrets/github-app.pem`. For dashboard sign-in,
also note the app's **Client ID** and generate a **client secret**; save the secret as
`secrets/github-client-secret`. "Request user authorization (OAuth) during installation"
is not needed, and the user token GitHub issues at sign-in is used once, to read who
signed in, then discarded — it never reaches the database or the logs.

### 2. Configure

```bash
cp .env.example .env      # fill in GITHUB_APP_ID and GITHUB_WEBHOOK_SECRET
mkdir -p secrets && mv ~/Downloads/*.private-key.pem secrets/github-app.pem
```

`.env` and `secrets/` are gitignored. The server refuses to start without a webhook
secret — without one, signatures cannot be verified.

**Sign-in.** The dashboard and every `/api` data endpoint require signing in with GitHub.
The API server needs `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` (or
`GITHUB_CLIENT_SECRET_PATH`), `PUBLIC_URL` and `ALLOWED_GITHUB_LOGINS`, and refuses to
start without them; see `.env.example`. Only the logins in `ALLOWED_GITHUB_LOGINS` can
sign in, and the list is rechecked on every request. `PUBLIC_URL` must be written the way
browsers send an origin (lowercase, no default port, no path). For local work without a
GitHub App, `docker-compose.yml` sets `AUTH_DISABLED=true`, which the server accepts only
with `APP_ENV=development`.

Signing in again from the same browser replaces its previous session. A failed sign-out
says so and leaves you signed in, rather than only forgetting the cookie. If an account is
removed from the allowlist while signed in, the dashboard shows the sign-in page with the
reason and a button to end that session. After signing in, or after an expired session
sends you to sign in, you return to the page you were on.

### 3. Start the stack

```bash
make up      # postgres + minio + server + worker
make logs
```

| Service | URL |
|-----------|-------------------------------------------|
| API | http://localhost:8080/healthz |
| MinIO console | http://localhost:9001 (`minioadmin` / `minioadmin`) |

Point a tunnel at `localhost:8080`, install the app on a repository, and push a
dependency change.

### Running without Docker

You need PostgreSQL, an S3-compatible store, `git`, and
[syft](https://github.com/anchore/syft) on `PATH`.

```bash
export DATABASE_URL='postgres://sbomdelta:sbomdelta@localhost:5432/sbomdelta?sslmode=disable'
make run-server      # applies migrations, then serves
make run-worker      # in another shell
```

---

## Tests

```bash
make test     # unit tests only; database tests skip themselves
```

The storage and queue tests run against a real PostgreSQL instance — they are what
verify the schema, the idempotency constraints, and the `SKIP LOCKED` semantics. Point
them at a **throwaway** database (they truncate tables):

```bash
docker compose up -d postgres
TEST_DATABASE_URL='postgres://sbomdelta:sbomdelta@localhost:5432/sbomdelta?sslmode=disable' \
  make test
```

---

## API

Everything under `/api` except the three sign-in endpoints needs a session; without one
the answer is `401 {"error":"authentication required"}`, and a signed-in login no longer
on the allowlist gets `403`. State-changing requests must also send
`X-SBOMDelta-Request: 1` from the dashboard's own origin. No CORS headers are sent.

| Method | Path | Purpose |
|--------|-----------------------------------|----------------------------------------|
| `POST` | `/webhooks/github` | GitHub event receiver (signature-verified) |
| `GET` | `/healthz` | Liveness plus queue depth (public) |
| `GET` | `/api/auth/github/login` | Start signing in with GitHub (public) |
| `GET` | `/api/auth/github/callback` | GitHub's redirect back (public, state-checked) |
| `POST` | `/api/auth/logout` | Sign out |
| `GET` | `/api/me` | Who is signed in |
| `GET` | `/api/repos` | Installed repositories |
| `GET` | `/api/repos/{id}` | One repository |
| `GET` | `/api/repos/{id}/scans` | Scan history |
| `GET` | `/api/repos/{id}/drift` | Drift timeline for charting |
| `GET` | `/api/repos/{id}/pulls` | Pull requests with their latest scan numbers |
| `GET` | `/api/pulls/{id}` | One pull request |
| `GET` | `/api/scans/{id}` | Scan status and result |
| `GET` | `/api/scans/{id}/components` | The full component list |
| `GET` | `/api/scans/{id}/drift` | What changed in this scan |
| `GET` | `/api/scans/{id}/vulnerabilities` | Advisories, plus whether enrichment has run |
| `GET` | `/api/scans/{id}/sbom` | Redirect to a presigned SBOM download |

`POST /api/repos/{id}/scans` and `POST /api/repos` answer `404 not available` for now:
queueing a scan by hand and registering a repository by URL return once they can be
offered safely.

---

## Layout

```
backend/
├── cmd/
│   ├── server/          API + webhook receiver; owns migrations
│   └── worker/          Queue consumer
├── internal/
│   ├── api/             HTTP handlers
│   ├── config/          Environment loading and validation
│   ├── diff/            The diff engine  ← the core
│   ├── github/          App auth, webhook verification, check runs
│   ├── models/          Persisted domain types
│   ├── queue/           Postgres job queue (SKIP LOCKED)
│   ├── sbom/            Clone, syft, CycloneDX normalization
│   ├── scanner/         The end-to-end scan pipeline
│   ├── storage/         Postgres queries and the SBOM blob store
│   └── worker/          Worker loop
└── migrations/          Embedded SQL schema

frontend/
├── src/
│   ├── api/             fetch wrapper; one place for error shape and aborts
│   ├── components/      Chart, tables, stat tiles, empty states
│   ├── composables/     useAsyncData: abort-safe loading that holds stale data
│   ├── lib/             Formatting helpers
│   ├── router/          Routes (views are lazily imported)
│   ├── views/           Repositories, Repository, Pull requests, PR, Scan
│   └── style.css        Design tokens, light and dark
└── vite.config.js       Dev proxy to the Go API
```

---

## Dashboard

Vue 3 + Vite + Tailwind, no component library and no charting library.

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173, proxies /api to localhost:8080
```

Pages: repository list → repository overview (drift timeline, scan history) → scan detail
(changes, components, vulnerabilities, licenses) and a per-pull-request risk page.

The drift timeline is hand-rolled inline SVG. A few deliberate choices there:

- **No second y-axis.** Component count lives in the hundreds while change counts live in
  single digits. Plotting both on one chart would need two scales, and the alignment
  between them would be arbitrary — inventing a correlation that is not in the data.
  Component count is a stat tile instead.
- **Three fixed series colors**, validated for colorblind separation, lightness band and
  chroma against both the light and dark surfaces. Slot 1 is always "added", slot 2
  "updated", slot 3 "removed", so filtering never repaints the survivors.
- **A table view beside the chart.** One series hue sits below 3:1 contrast on the light
  surface, so every value is reachable without relying on color — and without a hover.
- **Selective labels.** The endpoint column is labeled; the rest are carried by the axis,
  the legend and the per-column tooltip. A number on every bar goes unread.
- **Status colors are reserved** for severity and always ship with an icon and a written
  label, never color alone.

Dark mode is a selected palette rather than an inverted one, and follows the OS by
default with an explicit override in the header.

---

## Engineering notes

Some decisions worth explaining, because they are the interesting part:

**Postgres as the job queue, not Redis.** One stateful service instead of two, and — more
usefully — a job can be enqueued in the same transaction as the row it refers to.
`FOR UPDATE SKIP LOCKED` lets many workers drain one table without blocking each other.
Jobs whose lock outlives `WORKER_LOCK_TIMEOUT` are reclaimed, so a worker killed
mid-clone does not strand its work.

**Idempotency at three layers.** GitHub delivers at least once and retries any non-2xx.
Delivery IDs are recorded and replays dropped; scans are unique per
`(repository, commit, PR)`; job dedupe keys collapse repeat submissions. Re-running a
scan replaces its projection rather than colliding with it.

**Blob storage for SBOMs, Postgres for the projection.** A CycloneDX document for a
large repository is megabytes of JSON that no query planner should ever touch. Postgres
holds the queryable columns; S3/MinIO holds the archived artifact, byte-identical to what
the generator emitted. Downloads are presigned redirects, so multi-megabyte documents
never pass through the API's heap.

**syft as a subprocess, not a library.** Upgrading the scanner does not mean rebuilding
this service, and a scanner crash cannot take a worker down with it. Clones are shallow
and blobless — SBOM generation needs one tree, not the history — which is both a speed
and a disk-exhaustion concern on a shared worker.

**Scan failures are distinct from scan findings.** A check run that says "failure"
because syft crashed teaches people to ignore the check. A broken scan reports
`failure`; a scan that found drift reports `neutral` until the risk engine in Phase 5 can
justify blocking a merge.

**Credentials never reach a log.** Installation tokens are embedded in clone URLs, so git
errors are redacted before they reach a log line or a check body, and git is run with
`GIT_TERMINAL_PROMPT=0` so it can never block a worker waiting for credentials.

---

## Known gaps

- **Risk scoring is not implemented.** `risk_score` and `risk_delta` are present in the
  schema and the API but stay null until Phase 5. The drift timeline is currently measured
  in dependency movement, not risk, and the dashboard says so rather than showing a zero.
- **No vulnerability data yet.** The `vulnerabilities` table exists and is empty; OSV
  enrichment is Phase 4. `scans.enriched_at` is what the API uses to report whether a
  scan was ever analyzed, so the flag starts telling the truth the moment Phase 4 writes
  that column.
- **License policy is reporting only.** The dashboard lists what the SBOM declares and
  flags copyleft families for review; it does not decide whether a license is permitted.
- **Sign-in is single-tenant.** Everyone in `ALLOWED_GITHUB_LOGINS` sees every repository
  the App can reach; there is no per-user repository authorization yet. The allowlist
  matches logins, and GitHub logins can be renamed and later claimed by someone else, so
  remove a departed login from the list rather than relying on the account. The login
  a session is checked against is the one recorded at sign-in, so someone who renames
  their account stays signed in until the session expires (`SESSION_TTL`).
- **No scans on demand.** The scan-trigger and manual-registration endpoints are switched
  off; scans come from pushes, pull requests and initial scans.
- **Only the default branch is tracked for pushes.** Feature branches are covered through
  their pull requests.
- **`git clone` shells out**, so a repository whose dependency manifests need a build step
  to resolve fully (some Gradle and Bazel setups) will produce a thinner SBOM than a
  build-time scan would.
