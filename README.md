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

| Area | Scope | State |
|------|-------|-------|
| Inventory and SBOM delta | GitHub App, webhooks, clone, Syft/CycloneDX, blob archival, diff engine, drift history, per-user dashboard with tracking and on-demand scans | Implemented and tested |
| Vulnerability intelligence | OSV.dev lookup per component, severity, fixed versions, remediation, persisted findings | Implemented and tested; OSV client also checked against the live OSV.dev API |
| Pull request intelligence | Signature-verified, idempotent webhooks; dependency diff against the PR base; vulnerabilities introduced/resolved; GitHub check run with a documented conclusion policy | Implemented and tested with fixtures |
| Multi-repository impact | Which tracked repositories an advisory or a dependency reaches | Implemented and tested |
| Explainable risk scoring | Deterministic score from stored findings, with every point attributed | Implemented and tested |

"Tested" means automated tests against a real PostgreSQL and fake GitHub/OSV servers.
The end-to-end path on a deployment (a real push or pull request scanned by the worker and
reported on GitHub) has not been exercised as part of this change.

An unanalyzed scan never reads as clean: a scan whose components have not been (or could
not be) checked shows "checking" or "unavailable" with the reason, and has no risk score
rather than a zero.

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

### Vulnerabilities

After a scan stores its components, the worker asks [OSV.dev](https://osv.dev) — the
open vulnerability database that aggregates GitHub Security Advisories, PyPA, RustSec,
the Go vulnerability database and others — which advisories affect them
(`POST /v1/querybatch`, then `GET /v1/vulns/{id}`; no credentials).

- **Matching is OSV's.** Each component is asked about by its exact package URL and
  version (`pkg:npm/lodash@4.17.20`); OSV applies each ecosystem's own version rules.
  SBOMDelta never re-derives "is this version affected".
- **What can be checked.** Language ecosystems OSV indexes by package URL: npm, PyPI,
  Maven, Go, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, Swift, Hackage, CRAN.
  Components without a version, and OS packages (`deb`, `apk`, `rpm`, which need a
  distribution release a source-tree SBOM does not carry), are counted as *not checked*
  and the dashboard says how many.
- **Severity** is the CVSS v3 base score computed from the advisory's vector (FIRST
  specification formulas), else the source database's rating (GitHub's
  LOW/MODERATE/HIGH/CRITICAL), else *unrated*. CVSS v4 vectors are kept but not scored.
- **Fixes.** All fixed versions from the advisory's ranges for this package are stored;
  the recommended one is the lowest fixed version above the installed one, never a
  downgrade. Each finding carries remediation text derived from that.
- **One vulnerability, one finding.** OSV returns a record per publishing database (the
  GHSA, the Go or PyPA record, the CVE). Records linked by ID or alias are merged per
  component, keeping the most precisely rated one.
- **Failures are honest.** If OSV cannot be reached, the scan still completes with its
  dependency results, records why its vulnerabilities are unknown, and an `enrich` job
  retries with backoff. Scans stored before this existed are checked by a spaced
  background sweep when the worker starts. `OSV_DISABLED=true` turns lookups off (for
  offline development); scans then say so.

### Risk score

Deterministic and fully attributable (`backend/internal/risk`):

- Each finding scores by severity: critical **10**, high **6**, medium **3**, low **1**,
  unrated **2** (an unrated advisory is not treated as harmless).
- A finding on a **direct** dependency (when the SBOM records it) counts **×1.5**.
- The score is the sum, rounded to one decimal and capped at **100**.
- Levels: none (0), low (<10), medium (<25), high (<50), critical (50+).

`GET /api/scans/{id}/risk` returns every factor with its points, the top contributing
findings and the rule above; the dashboard shows it under **Why?**. Per scan, the delta
against the base scan is stored, and each dependency change is credited with the points
it added or removed. Nothing is estimated: no exploit probabilities, no reachability.

### Pull requests and check runs

Webhooks are rejected unless their HMAC-SHA256 signature verifies, delivery IDs make
redeliveries no-ops, and one scan exists per commit, so a PR's scan is queued once. A
pull request is diffed against its base commit, and its vulnerabilities are compared with
the base scan's by (package, advisory), so upgrading to a still-affected version is
*unchanged*, not resolved-and-reintroduced. Closing or merging a PR records its state.

The check run (posted with the existing App's Checks permission) leads with what the PR
introduces, and concludes:

| Conclusion | When |
|------------|------|
| `failure` | a critical or high vulnerability is introduced, or the scan itself broke |
| `neutral` | dependencies changed, a lower-severity vulnerability is introduced, or vulnerability data is unavailable |
| `success` | nothing changed and nothing new is vulnerable |

A failing check blocks a merge only where branch protection requires it. When a delayed
vulnerability lookup succeeds, the check run is updated.

### Multi-repository impact

`/impact` in the dashboard (and `GET /api/impact/vulnerabilities`,
`GET /api/impact/components?q=`) answers "which of my tracked repositories does this
advisory, or this package, reach?" at each repository's latest default-branch scan,
with the coverage stated: repositories without a completed or analyzed scan cannot
appear, and the page says how many those are.

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

**Your repositories.** While GitHub's token is in hand at sign-in, the server asks GitHub
which repositories you can reach through the App's installations
(`GET /user/installations` and `/user/installations/{id}/repositories`, every page) and
stores that list for your account; the token is then discarded as before. That list is
"All Repos" on the dashboard, and it is the authorization rule for everything: a
repository, scan, pull request or SBOM outside your list answers `404`. **Refresh from
GitHub** re-reads it by signing in again (GitHub skips its prompt for an app you already
authorized). If GitHub refuses the listing, you stay signed in with an empty list and the
reason shown, never a stale list.

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

The OSV client's tests use a fake OSV server. To check it against the real OSV.dev API
(needs the network; not part of CI):

```bash
cd backend && go test -tags osvlive ./internal/osv -run TestLiveOSV -v
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
| `GET` | `/api/me/repositories` | Your repositories from GitHub ("All Repositories"), tracked or not, each with its latest and last completed branch scan: `?q=`, `?page=`, `?perPage=` (max 100), `?exclude=tracked`, plus when the list was read |
| `GET` | `/api/me/tracked` | Your tracked repositories with their latest and last completed scans, vulnerability summary and risk |
| `PUT` | `/api/me/tracked/{id}` | Track a repository you can access (no scan) |
| `DELETE` | `/api/me/tracked/{id}` | Stop tracking (scan history is kept) |
| `GET` | `/api/me/scans` | Last scans of your tracked repositories: `?limit=`, `?repositoryId=` |
| `GET` | `/api/impact/vulnerabilities` | Advisories across your tracked repositories, with coverage |
| `GET` | `/api/impact/components?q=` | A dependency across your tracked repositories |
| `POST` | `/api/repos/{id}/scans` | Scan the default branch head and track the repository: `202 {scan, outcome}` |
| `GET` | `/api/repos` | Your repositories SBOMDelta has stored |
| `GET` | `/api/repos/{id}` | One repository |
| `GET` | `/api/repos/{id}/scans` | Scan history |
| `GET` | `/api/repos/{id}/drift` | Drift timeline for charting |
| `GET` | `/api/repos/{id}/pulls` | Pull requests with their latest scan numbers |
| `GET` | `/api/pulls/{id}` | One pull request |
| `GET` | `/api/scans/{id}` | Scan status and result |
| `GET` | `/api/scans/{id}/components` | The full component list |
| `GET` | `/api/scans/{id}/drift` | What changed in this scan |
| `GET` | `/api/scans/{id}/vulnerabilities` | Advisories with fixes and remediation, plus whether and how the scan was checked |
| `GET` | `/api/scans/{id}/vulnerability-changes` | Advisories introduced and resolved against the base scan |
| `GET` | `/api/scans/{id}/risk` | Risk score with factors and method, or why it is not scored |
| `GET` | `/api/scans/{id}/sbom` | Redirect to a presigned SBOM download |

Every `/api/repos/…`, `/api/scans/…` and `/api/pulls/…` route answers `404` for a
repository outside the signed-in user's list from GitHub, exactly as for one that does not
exist.

`POST /api/repos/{id}/scans` takes no input but the repository. The server asks GitHub, as
the App installation, which commit the default branch points at, then creates a `manual`
scan through the same one-scan-per-commit rule as push scans and queues the ordinary scan
job, so the worker clones, runs Syft, stores the CycloneDX SBOM and diffs it like any other
scan. `outcome` is `queued`, `in_progress` (that commit is being scanned), `up_to_date`
(that commit already has results, so nothing is repeated) or `retried` (its earlier scan
failed). `409` means the repository cannot be scanned (`reason`: `no_access`,
`no_branch_head`, `renamed`); `502` means GitHub could not be reached. `POST /api/repos`
(registering a repository by URL) stays `404 not available`. When the commit is already
scanned but its vulnerability lookup never succeeded, the request also queues that lookup.

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
│   ├── osv/             OSV.dev client, CVSS v3 scoring, fix selection
│   ├── queue/           Postgres job queue (SKIP LOCKED)
│   ├── risk/            Deterministic risk model and finding comparison
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
│   ├── views/           Repositories, Repository, Pull requests, PR, Scan, Impact
│   └── style.css        Design tokens, light and dark
└── vite.config.js       Dev proxy to the Go API
```

---

## Dashboard

Vue 3 + Vite + Tailwind, no component library and no charting library.

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173, proxies /api to 127.0.0.1:8080
```

Pages: the dashboard (the security overview cards and shortcuts to the other pages; it
repeats no listings), Repositories (Tracked Repositories above All Repositories), Last Scans, Impact across repositories, and from any repository its report (risk, drift
timeline, scan history) → scan detail (risk explanation, vulnerability changes, changes,
components, vulnerabilities, licenses) and pull request pages.

How the two repository sections behave:

- **All Repositories** lists every repository your account can reach, tracked or not.
  Each has **Scan** (never completed a scan) or **Scan again**, and **Track** or
  **Untrack**. Scanning never tracks and tracking never scans.
- **Tracked Repositories** lists the repositories you track that have a completed scan.
  A tracked repository without one is named in a note instead, since it has no report.
  A repository can be in both sections; both rows always agree.
- Under each name: `Last scanned on DD-MM-YYYY at HH:MM`, the finish time of the last
  completed scan in the viewer's time zone, or `Not scanned yet`. A queued, running or
  failed scan shows as a status beside it and never replaces it.
- The name opens the report only once a completed scan exists, and stays a link while a
  rescan runs or after a later scan fails.

The header has Back (previous app page, else the dashboard), the navigation, a light/dark
toggle (a saved choice wins, otherwise the OS preference; applied before first paint) and
the signed-in GitHub login with Sign out.

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
because syft crashed teaches people to ignore the check, so the check text always says
which it is. Drift alone is `neutral`; only an introduced critical or high vulnerability
fails a pull request.

**Credentials never reach a log.** Installation tokens are embedded in clone URLs, so git
errors are redacted before they reach a log line or a check body, and git is run with
`GIT_TERMINAL_PROMPT=0` so it can never block a worker waiting for credentials.

---

## Known gaps

- **Vulnerability coverage is OSV's.** Components OSV cannot be asked about (no version,
  OS packages, unsupported ecosystems) are counted as not checked, and an advisory OSV
  does not have is not reported. CVSS v4-only advisories show as unrated unless their
  database rates them.
- **The risk score measures known vulnerabilities only**, weighted by severity. It does not
  model exploitability, reachability or licenses.
- **Impact covers latest default-branch scans of tracked repositories.** Pull request
  scans and untracked repositories are not part of it.
- **License policy is reporting only.** The dashboard lists what the SBOM declares and
  flags copyleft families for review; it does not decide whether a license is permitted.
- **Repository access is read at sign-in.** Each user sees the repositories GitHub listed
  for them when they last signed in. Access gained or lost on GitHub since then shows after
  **Refresh from GitHub** or the next sign-in (sessions last `SESSION_TTL`). Scanning
  still requires the App's installation to reach the repository at the time of the scan.
  The allowlist matches logins, and GitHub logins can be renamed and later claimed by
  someone else, so remove a departed login from the list rather than relying on the
  account. The login a session is checked against is the one recorded at sign-in.
- **A repository appears in "All Repos" before it can be scanned** when the App was just
  installed: GitHub lists it for the user at once, but SBOMDelta stores it when the
  installation's reconciliation runs. It shows as syncing until then.
- **Scans on demand cover the default branch only**, at its current head. Manual
  registration of repositories by URL stays off.
- **Only the default branch is tracked for pushes.** Feature branches are covered through
  their pull requests.
- **`git clone` shells out**, so a repository whose dependency manifests need a build step
  to resolve fully (some Gradle and Bazel setups) will produce a thinner SBOM than a
  build-time scan would.
