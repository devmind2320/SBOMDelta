# Production deployment

Pushes to `main` deploy to the production EC2 host once CI passes, using
GitHub OIDC (no stored AWS keys) and AWS Systems Manager (no SSH).
`.github/workflows/cd.yml` drives it; on the instance, `deploy/bootstrap.sh`
prepares the run and `deploy/deploy.sh` does the work.

## How it works

1. **CI** runs on the push: Go tests, including the database-backed ones
   against a Postgres service; lint; the frontend build; and tests and checks
   for the deployment scripts.
2. **CD** starts when CI succeeds for a push to `main` (or by hand). It
   deploys the **exact commit CI tested**, confirms the commit is on `main`,
   assumes the deploy role through OIDC, and sends one SSM command. A manual
   deploy must find a successful CI run for its commit too (see
   [Manual runs](#manual-runs)).
3. **On the instance**, the SSM command is `deploy/bootstrap.sh`, taken from
   `main`. It takes the host's deployment lock **before** anything else,
   fetches `main` into the deployment checkout as the checkout's owner, checks
   out the commit, and runs that commit's `deploy/deploy.sh` from a private
   copy in `/run`. The script inherits the lock and keeps it until it exits.
4. CD **waits for the command to finish**, shows its output (redacted), and
   fails unless the command succeeded **and** printed a result marker that
   fits the run. It then checks the public site from outside: `/api/repos`
   answers (with repositories, or with the server's own JSON `401` once
   dashboard sign-in is deployed), and `index.html` matches the build that
   was published.

Only one deployment runs at a time. GitHub's concurrency group queues runs,
and the host lock (`/run/lock/sbomdelta-deploy.lock`) covers what GitHub
cannot: cancelling a workflow run does **not** stop its SSM command. A second
deployment that finds the lock held exits at once (code 75), without fetching
or checking anything out.

### Two directories, two roles

| Directory | Role | What deployments do to it |
|---|---|---|
| `/home/ec2-user/SBOMDelta-deploy` | Clean git checkout. The **source** of the commit being deployed. | Fetch and check out the commit. Nothing else. |
| `/home/ec2-user/SBOMDelta` | The production **runtime**: the production `docker-compose.yml`, `.env`, `secrets/`, `nginx/default.conf`, `frontend/dist`. | Only the contents of `frontend/dist` change. Git is never run here, so the locally modified production `docker-compose.yml` cannot be overwritten. |

The production `docker-compose.yml` has the same name as the repository's
development file, which is exactly why git is kept out of that directory.

### What `deploy.sh` does

**Preflight.** Nothing changes until all of these pass:
- the source checkout is exactly the requested commit, unmodified, and the
  running script is that commit's `deploy/deploy.sh`;
- the production Compose file exists, is not inside the deployment checkout,
  and there is **no** Compose override file next to it;
- the Compose **project name is read from the running containers' labels**,
  and every container was created from **exactly** the production Compose
  file: no extra `-f` files and no override;
- the `server`, `worker`, `postgres`, `minio` and `nginx` services exist in
  the production Compose file;
- `server`, `postgres`, `minio` and `nginx` each have **exactly one**
  container (one-off `docker compose run` containers are ignored), MinIO is
  running, and `sbomdelta-nginx` is the `nginx` service's container. Two
  containers for a service fail the preflight, listing their names and
  states;
- the `worker` has **at most one** container, in any state. With none (as in
  production today), preflight says so, takes the worker's image name from
  the production Compose file (naming a service in `compose config --images`
  also lists everything it depends on, so the worker's image is the one left
  after removing every other service's images; anything other than exactly
  one image stops the preflight), skips the checks that need an existing worker
  (its current image and configuration hash), and a deployment creates the
  worker. With two or more, preflight fails and lists them;
- the images the services run are what the Compose file specifies;
- recreating `server` would not restart other services (no
  `depends_on: {server: {restart: true}}` outside the worker);
- the server and worker run the configuration Compose resolves now (their
  `com.docker.compose.config-hash` labels match `compose config --hash`), so
  recreating them changes only the image. A deliberate change to the
  production `docker-compose.yml` or `.env` therefore has to be applied on
  the current image first; see
  [Changing the production configuration](#changing-the-production-configuration);
- the running server already has the dashboard sign-in settings the new
  server needs to start (`GITHUB_CLIENT_ID`,
  `PUBLIC_URL` equal to `https://sbomdelta.website`, no `AUTH_DISABLED`), and
  its client secret file exists, is a regular file, is not empty and is
  readable **by the server's own user, through its real mounts**: the check
  runs inside the server container with `docker exec`, as the image's user
  (uid 10001). It prints setting names, the secret's path and that uid --
  never a value or the secret. A world-writable secret file fails; a
  world-readable one is a warning;
- the Postgres data volume exists; `.env` and the GitHub App key exist
  (checked for presence only, never read); Postgres is healthy;
- there is free disk for the backup and the image builds;
- `sbomdelta-nginx` serves exactly `/home/ec2-user/SBOMDelta/frontend/dist`,
  publishes port 443 on the host, passes `nginx -t`, and runs the
  configuration that is on disk (see [Nginx](#nginx));
- `sbomdelta-nginx` still holds **that very directory**, not just the same
  path: `frontend/dist` and its `index.html` have the same inode numbers on
  the host as `/usr/share/nginx/html` and its `index.html` inside the
  container. Docker binds the directory that existed when the container
  started, so a `frontend/dist` moved, re-created or copied over since then
  leaves Nginx serving the old directory, and a publish would not reach it.
  A mismatch, or any failure to read the inodes, stops the preflight; see
  [Frontend bind mount](#frontend-bind-mount). The script never restarts
  Nginx;
- the site already works **through Nginx**: `/` is the current `index.html`,
  and an anonymous `https://sbomdelta.website/api/repos` answers the way the
  running server must (see [API smoke expectations](#api-smoke-expectations)).
  For a server with sign-in, an anonymous `POST /api/auth/logout` (no cookie,
  no CSRF header) must also reach the server and get its own
  `{"error":"cross-site request refused"}`: that proves Nginx passes the
  `POST`, `PUT` and `DELETE` requests that sign-out, scans and tracking use.
  The server refuses the probe before any handler runs, so it changes nothing.
  The requests go to Nginx on this host, so TLS, the server name and the
  proxying are all exercised;
- the running server reports healthy at `http://127.0.0.1:8080/healthz`
  (`HEALTH_URL`). This is a hard failure: the deployment uses that URL to
  decide whether the new server is healthy, so if it cannot be reached now, a
  deployment would apply migrations and then roll back;
- the running server is **connected to that same Postgres** (its container
  IP appears in `pg_stat_activity`), so the backup and migration checks cover
  the database the server actually uses.

**Build.** While the live services keep running, it builds the server and
worker images from the source checkout, and the frontend inside a Node
container (no Node needed on the host).

**Backup.** `pg_dump -Fc` of the production database to
`/home/ec2-user/deployment-backups` (mode 600; verified with
`pg_restore --list`), plus a tarball of the current `frontend/dist`. This
happens before the server is recreated, so before any migration runs.

**Server.** Recreated with `up -d --no-deps --no-build` using the production
Compose file and project. It applies migrations on start. The script waits for
`/healthz` to report `ok`, confirms the newest migration is recorded in the
database it just backed up, points Nginx at the new container if its address
changed, and then requires an anonymous `/api/repos` **through Nginx** to get
the server's exact sign-in refusal, `401 {"error":"authentication required"}`.

**Worker.** Created, or recreated and started, only after that, and required
to run steadily without restarting. A worker that was stopped before the
deployment is started by it.

**Frontend.** Published into the bind-mounted `frontend/dist` **in place**:
assets first, `index.html` last, then stale files under `assets/` pruned. The
directory is never replaced (that would break the bind mount). Nothing outside
`assets/` is deleted, so `.well-known/` and any other files stay. The script
confirms the Nginx container sees the new `index.html`, then runs the final
smoke test through Nginx: `/api/repos` refuses anonymous requests with that
exact response, and `/` is the new build.

**Record.** The deployed commit goes to `current-sha` (used only to skip
older commits) and `deploy-history.log` in the backup directory, and the run
prints its result marker, including `api=`: how the running server image
answers an anonymous `/api/repos`.

If anything fails after the switchover, **including a failed smoke test
through Nginx**, the previous server and worker images and the previous
frontend are restored automatically, Nginx is pointed back at the restored
server if needed, and the site is checked through Nginx again. A previous
worker comes back in the state it was in (running, or created but not
started). A worker that **did not exist** before the deployment has nothing to
go back to, and the script never stops or removes containers, so it is left
running the new image; see [Rollback](#rollback). **Migrations
are never rolled back.** They are additive, so the previous release runs on
the new schema; the pre-deploy database dump is there if a migration itself
is the problem.

Automatic deployments skip a commit that is older than the one already
deployed, so a late CI result cannot roll production backwards.

### API smoke expectations

Every smoke test requests `/api/repos` without signing in. Only two answers
count: the sign-in refusal of a server with dashboard sign-in -- HTTP 401 with
exactly the body `{"error":"authentication required"}` -- and the anonymous
repository list of a server that predates sign-in. Any other 401 (from Nginx,
a load balancer, another application, or with any other body) fails.

How each server must answer is read from **its own image**. From the release
that added sign-in, the server image carries the label
`org.sbomdelta.dashboard-signin=required` (`backend/Dockerfile`). An image
with that label must give the refusal; an image without it predates sign-in
and must list repositories. Any other label value, or an image that cannot be
inspected, stops the deployment rather than guessing. The label travels with
the image, so it holds whichever image is running, being rolled back to, or
newly built -- and nothing on the host can make it stale. `current-sha` plays
no part in it.

| Check | Server being checked | Required answer |
|---|---|---|
| Preflight | the running server, by its image's label | the refusal if labelled, the repository list if not |
| After the build, before anything is switched | the new image | must carry the label, or the deployment stops |
| After the switch, and the final smoke test | the new server | **the sign-in refusal**; a repository list fails |
| Rollback | the previous image, by the label read in preflight | what that image declares; with nothing read, no answer passes |
| CD's check from outside, after a deploy | the deployed image: `api=` in the result marker, which `deploy.sh` reads from the label; checked against the label in that commit's `backend/Dockerfile` | what the image declares; a signed-in image that lists repositories fails at once, and a disagreement between the two fails |
| CD's check after `skipped-older` (nothing deployed) | whatever runs | either real answer; anything else fails |

So the first rollout of sign-in passes on its own -- the running image has no
label and lists repositories; the new one has it and refuses -- and every
later deployment holds the running server to the refusal, with nothing to
change by hand. Redeploying an older commit (see [Rollback](#rollback)) works
the same way in reverse: its `deploy.sh` predates the label and reports no
`api=`, so CD reads that commit's `Dockerfile`, finds no label, and expects
the repository list.

### Nginx

The live configuration proxies by service name with no `resolver`:

```nginx
location /api/ {
    proxy_pass http://server:8080/api/;
```

Nginx resolves `server` once, when it loads its configuration, and keeps that
address. Recreating the server container can give it a new address, and Nginx
would then keep sending requests to the old one. So after recreating the
server, `deploy.sh` compares the server's address with the one Nginx resolved:

- **unchanged:** Nginx is left alone;
- **changed:** it runs `nginx -t` and then `nginx -s reload`. A reload is
  graceful: no container restart, in-flight requests finish, and nothing on
  disk is modified.

**Methods.** The dashboard sends `GET` and `HEAD` reads and three kinds of
writes under `/api/`: `POST` (`/api/auth/logout`, `/api/repos/{id}/scans`),
`PUT` and `DELETE` (`/api/me/tracked/{id}`). Restrict the location to exactly
those methods, never to `GET` alone:

```nginx
location /api/ {
    limit_except GET POST PUT DELETE {
        deny all;
    }

    proxy_pass http://server:8080/api/;
    # ... proxy headers unchanged
}
```

`limit_except GET` also allows `HEAD`. Every other method (`PATCH`, `OPTIONS`,
`TRACE`, ...) gets Nginx's 403 before reaching the server. The server still
checks every allowed write: sign-in (`auth.RequireUser`), and the CSRF header
plus same-origin `Origin` (`auth.SameOrigin`). A `GET`-only `limit_except`
answers every write with Nginx's HTML 403 page: sign-out reports "the server
refused the sign-out request", and scans and tracking fail. Preflight detects
that (see [What `deploy.sh` does](#what-deploysh-does)) and stops.
`/webhooks/github` is a separate location and must allow `POST`.

A reload applies whatever configuration is on disk, so preflight requires that
no `*.conf` file under `/etc/nginx` in the container changed after Nginx last
loaded its configuration (the start time of its oldest worker). An edit that
has not been applied, such as a `limit_except` change, stops the
preflight. Apply it (or revert it) deliberately first, then run preflight
again. Files outside `/etc/nginx` that the configuration includes (for example
certbot's `options-ssl-nginx.conf`) are not covered by this check.

Nginx only proxies `/api/` and `/webhooks/github`, so `/healthz` is checked
directly on the server, never through Nginx or the public URL.

### Time limits and termination

SSM stops the command after 3600 seconds. `deploy.sh` keeps inside its own
limit (`DEPLOY_TIME_LIMIT`, 3300 seconds): builds and the backup run under
`timeout`, and the switchover does not start unless `SWITCHOVER_RESERVE`
(900 seconds) is left, enough to finish it or roll it back. If the script is
sent SIGTERM, SIGINT or SIGHUP (for example by SSM or by cancelling the
command), it exits through the same rollback path. That is best effort: bash
handles a signal only between commands, and nothing can catch SIGKILL.

Cancelling the GitHub run does not cancel the SSM command, and the workflow
deliberately does not cancel it either: stopping a deployment in the middle
of a switchover is worse than letting it finish or roll back. A cancelled run
prints the command ID; check the command's result in Systems Manager before
starting another deployment (until it finishes, the host lock refuses one
anyway).

### What it never does

- `docker compose down`, `rm` or `stop`, `docker volume rm`, any `prune`,
  `git clean`, destructive SQL, or anything else that removes containers,
  volumes or data. CI runs `deploy/tests/check-destructive.sh` over the
  deployment path and fails if any of these appear outside a comment.
- Run Compose without the production file and project name, or ever use the
  repository's development `docker-compose.yml`.
- Touch `.env`, `secrets/`, `nginx/default.conf`, TLS certificates, or the
  certbot webroot. Nginx is reloaded only in the one case above, never
  restarted or reconfigured.
- Print environment values, full Compose configuration, credentials or keys.
  Database commands expand their connection settings inside the Postgres
  container; Compose is only asked for service names, images and
  configuration hashes; response bodies are never printed; build output goes
  to a mode-600 log on the host, and only a redacted tail is shown on
  failure. The workflow redacts all instance output again with
  `deploy/redact.sed`, which masks credentials in URLs, `key=value` and
  `key: value` credentials, `Authorization` headers and bearer tokens, PEM
  private keys (even cut off), and common token formats (GitHub, AWS access
  key IDs, Slack, JWTs, Google, `sk-` keys, Stripe).

### What a preflight run changes

Preflight does not touch services, Nginx, the database or production files.
Its side effects on the host are:

- the deployment checkout is fetched and checked out at the commit;
- the lock file `/run/lock/sbomdelta-deploy.lock` is created if missing
  (`/run` is a tmpfs, cleared at boot);
- a private copy of `deploy.sh` lives in `/run/sbomdelta-deploy.*` while the
  run lasts, and is removed when it exits;
- short-lived temporary files in `/tmp` hold smoke-test responses, removed
  straight away;
- read-only requests: `GET /api/repos` and `GET /` through Nginx, `GET
  /healthz` on the server, read-only database queries, `nginx -t`, and
  `stat` of the web root inside the Nginx container;
- inside the server container, as its own user: `test`, `grep -q` and `find -perm`
  on the client secret file, which print only a status line per check.

It does **not** create or change `/home/ec2-user/deployment-backups`. A
deploy creates that directory (mode 700) and its `logs/` only if they are
missing, and never changes the mode of an existing one.

## Manual runs

**Actions → CD → Run workflow**, branch `main`:

| Input | Default | Meaning |
|---|---|---|
| `mode` | `preflight` | `preflight` checks the host and prints the plan; `deploy` deploys. |
| `sha` | tip of `main` | The commit to deploy. It must be on `main`. |
| `emergency_override` | off | See below. |
| `override_reason` | empty | Required with the override. |

A manual **deploy** requires that the latest completed CI run for a push of
that exact commit to `main` succeeded. A commit that was never the tip of a
push (so CI never ran on it), or whose CI failed, is refused.

**Emergency override.** Only when production is broken and the fix cannot
wait for CI: tick `emergency_override` and give an `override_reason`. The run
shows a warning, the job summary records the reason, and the host's
`deploy-history.log` records `ci_override=1`. Every preflight check and every
post-deploy check still applies. It is never the default.

## First deployment (manual, reviewed)

The first run applies migration `0004` and starts repository reconciliation,
which marks repositories the GitHub App can no longer reach as inaccessible.
Do it by hand:

1. Complete the [prerequisites](#prerequisites).
2. **Actions → CD → Run workflow**, branch `main`, mode **`preflight`**. Read
   the output: the project name, images, applied migrations, Nginx state, and
   plan. See [What a preflight run changes](#what-a-preflight-run-changes).
3. If the preflight is right, run it again with mode **`deploy`**, and watch.
4. Afterwards, check the dashboard: active repositories, the "No longer
   accessible" section, and that repository history still opens.
5. Only then set the repository variable **`DEPLOY_AUTOMATIC`** to `true`.
   Until it is set, CI successes on `main` do not deploy.

### First deployment of dashboard sign-in

The release that adds sign-in needs new server settings, and the new server
refuses to start without them. Preflight will not let a deployment change the
configuration and the image at once, so the settings go in first, on the
image that is running now, and the deployment then changes only the image.
In order:

1. On GitHub, in the App's settings: set the **Callback URL** to
   `https://sbomdelta.website/api/auth/github/callback`, note the **Client
   ID**, and generate a **client secret**.
2. On the instance, save the client secret as
   `/home/ec2-user/SBOMDelta/secrets/github-client-secret` (see
   [Client secret file](#client-secret-file)).
3. Add the [sign-in settings](#prerequisites) to the `server` service's
   `environment:` in the production `docker-compose.yml`. Change no other
   service.
4. Apply them on the current image:
   [Changing the production configuration](#changing-the-production-configuration).
   The running server predates sign-in and ignores the new settings, so the
   site behaves exactly as before.
5. **Actions → CD → Run workflow**, mode **`preflight`**. It must report
   `ok: dashboard sign-in settings present in the running server` and that the
   server runs the configuration Compose resolves. Fix anything it reports and
   repeat; nothing changes until it passes.
6. Run it again with mode **`deploy`**. After the switch, an anonymous
   `/api/repos` must get the sign-in refusal; otherwise the deployment rolls
   back to the previous image, which still runs with the settings from step 4.
7. Sign in at `https://sbomdelta.website` with an allowed account, and sign
   out again.

### Opening SBOMDelta to every GitHub account

From the multi-user release on, `ALLOWED_GITHUB_LOGINS` and
`ALLOWED_INSTALLATION_ACCOUNTS` are optional restrictions. While they are set,
the release behaves as before for those accounts (an installation also has to
be connected by a signed-in user, which the owner's already is). Opening the
dashboard is therefore two separate, reversible steps: deploy the code with
the settings untouched, then remove the settings.

1. **Deploy** the release through CD (`preflight`, then `deploy`) with the
   production `docker-compose.yml` and `.env` unchanged. Sign in as the owner
   and check the dashboard and a **Scan** still work. Until step 3, a rollback
   to the previous release needs nothing else.
2. **GitHub App settings** (on GitHub, not the instance): the App is public;
   set **Setup URL** to `https://sbomdelta.website/api/auth/github/login` and
   tick **Redirect on update**, so someone who installs it lands back in a
   refreshed sign-in. Optionally add `GITHUB_APP_SLUG` (the App's URL name)
   to the `server` service for the dashboard's **Add repositories** link.
3. **Remove the restrictions**: delete `ALLOWED_GITHUB_LOGINS` from the
   `server` service and `ALLOWED_INSTALLATION_ACCOUNTS` from both `server` and
   `worker` in the production `docker-compose.yml`, and their lines in `.env`.
   Keep a copy of both files first. Apply the change on the current images:
   [Changing the production configuration](#changing-the-production-configuration),
   once for `server` and once for `worker`. The server log then says
   `sign-in open to any GitHub account`.
4. **Check** with a second GitHub account: sign in, install the App on that
   account with one repository, come back (or **Refresh from GitHub**). The
   repository appears and gets a first scan; the owner's account does not see
   it, and it does not see the owner's.
5. **Then run a CD `preflight`** and confirm it passes with the new
   configuration, so the next deployment is not held up by it.

**Rolling back after step 3.** The release before this one refuses to start
without both settings. Restore the two files saved in step 3 and apply them
(step 3's procedure) *before* rolling back to it, or the rolled-back server
and worker will not start. Rolling back only the configuration (restoring the
files and applying them) re-restricts the dashboard without changing images.

## Configuration

### GitHub repository variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Required | Default in `cd.yml` |
|---|---|---|
| `DEPLOY_AUTOMATIC` | Set to `true` to enable deploy-on-push, after the first manual deploy | unset: automatic deploys are skipped |
| `AWS_ROLE_ARN` | No | `arn:aws:iam::153844980148:role/SBOMDelta-GitHub-Deploy-Role` |
| `AWS_REGION` | No | `ap-south-1` |
| `EC2_INSTANCE_ID` | No | `i-0296a251d132fc195` |
| `DEPLOY_DIR` | No | `/home/ec2-user/SBOMDelta-deploy` (passed to `deploy.sh` as `--deploy-dir`) |
| `PUBLIC_URL` | No | `https://sbomdelta.website` |

No GitHub secrets are needed. The CI check for manual deploys uses the
workflow's own token with `actions: read`. If an `EC2_SSH_KEY` secret is left
over from the earlier SSH-based workflow, delete it.

### IAM: the deploy role (not verifiable from the repository)

**Trust policy.** The role must trust `token.actions.githubusercontent.com`
with:
- `token.actions.githubusercontent.com:aud` = `sts.amazonaws.com`
- `token.actions.githubusercontent.com:sub` =
  `repo:devmind2320/SBOMDelta:ref:refs/heads/main`

Both manual runs (restricted to `main`) and `workflow_run` runs (which execute
on the default branch) present that subject. If a GitHub `environment:` is
ever added to the job, the subject becomes
`repo:devmind2320/SBOMDelta:environment:<name>`, and the trust policy must
change with it.

**Permissions.** Minimum:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ssm:ap-south-1::document/AWS-RunShellScript",
        "arn:aws:ec2:ap-south-1:153844980148:instance/i-0296a251d132fc195"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetCommandInvocation",
      "Resource": "*"
    }
  ]
}
```

`GetCommandInvocation` does not support resource-level restriction, hence
`"*"`. The earlier workflow only ever called `SendCommand`, so this permission
may be missing; the first run will fail clearly at the waiting step if it is.

### Prerequisites

**The EC2 instance needs:**
- the SSM agent online, with an instance profile that includes
  `AmazonSSMManagedInstanceCore`;
- Docker with the Compose v2 plugin **available to root** (SSM runs as root;
  a plugin installed only in `~ec2-user/.docker/cli-plugins` is not);
- `git`, `curl`, `tar`, `gzip`, coreutils (`timeout`), util-linux (`flock`,
  `runuser`) and procps (`ps`, which `docker top` uses). Amazon Linux 2023
  ships these;
- `/home/ec2-user/SBOMDelta-deploy` as a **git clone of this repository**
  whose `origin` can fetch `main` as its owner. For a private repository that
  means a read-only deploy key or equivalent. It must have no local changes to
  tracked files;
- outbound access to GitHub, Docker Hub (`golang`, `alpine`, `anchore/syft`,
  `node` images) and the npm registry;
- at least 5 GB free for Docker, plus twice the database size free in
  `/home/ec2-user/deployment-backups`.

**Dashboard sign-in settings (required from the release that adds sign-in).**
The server refuses to start without these. Preflight checks them in the
running server, so a deployment stops before changing anything if they are
missing. Add them to the `server` service and apply them on the current image
before deploying that release ([First deployment of dashboard
sign-in](#first-deployment-of-dashboard-sign-in)). They are not in this
repository and must not be:

| Setting | Value |
|---|---|
| `GITHUB_CLIENT_ID` | The GitHub App's Client ID |
| `GITHUB_CLIENT_SECRET_PATH` | `/run/secrets/github-client-secret` (see [Client secret file](#client-secret-file)); `GITHUB_CLIENT_SECRET` inline also works but puts the secret in the environment |
| `PUBLIC_URL` | `https://sbomdelta.website` |
| `SESSION_TTL` (optional) | Default `12h` |
| `GITHUB_APP_SLUG` (optional) | The App's URL name; the dashboard's **Add repositories** link is built from it |
| `ALLOWED_GITHUB_LOGINS` (optional) | Restricts sign-in to these logins. Leave unset for a multi-user deployment |

**Optional installation restriction, in both the `server` and the `worker`
service:** `ALLOWED_INSTALLATION_ACCOUNTS`, comma-separated GitHub **numeric
account IDs**, scans only installations on those accounts. Leave unset for a
multi-user deployment. See
[Opening SBOMDelta to every GitHub account](#opening-sbomdelta-to-every-github-account).

The GitHub App's **Callback URL** must be
`https://sbomdelta.website/api/auth/github/callback`. Nginx needs no change:
it already proxies `/api/`. Never set `AUTH_DISABLED` in production; the
server rejects it outside `APP_ENV=development`, and preflight rejects it too.
`PUBLIC_URL` must be written exactly as browsers send the origin: lowercase,
`https`, no port, no path. The server refuses any other spelling.

#### Client secret file

| | |
|---|---|
| Host path | `/home/ec2-user/SBOMDelta/secrets/github-client-secret` |
| Path in the server container | `/run/secrets/github-client-secret`, through the existing `./secrets:/run/secrets:ro` bind mount (no new mount) |
| Owner | uid `10001`, gid `10001` -- the `sbomdelta` user the server image runs as (`backend/Dockerfile`) |
| Mode | `0400` |
| Content | the client secret on one line; surrounding whitespace is ignored |

The `secrets/` directory must already let uid 10001 reach the GitHub App key,
so it lets it reach this file too. To create the file without the secret
appearing on screen or in shell history (paste it at the silent prompt, then
press Enter):

```bash
cd /home/ec2-user/SBOMDelta
sudo bash -c 'umask 077; IFS= read -rs s && printf "%s\n" "$s" > secrets/github-client-secret'
sudo chown 10001:10001 secrets/github-client-secret
sudo chmod 0400 secrets/github-client-secret
```

Preflight confirms the server's user can read it, without reading it out.

**Facts only the instance can confirm.** Preflight checks each of these and
stops if one does not hold. They cannot be verified from the repository,
because the production `docker-compose.yml` and `nginx/default.conf` exist
only on the instance:

| Requirement | Why | If it fails |
|---|---|---|
| The server answers at `http://127.0.0.1:8080/healthz` | The repository's development Compose file publishes `8080:8080`; the production file must too | Publish the port, or set `HEALTH_URL` |
| `sbomdelta-nginx` publishes 443/tcp on an IPv4 host address | The smoke tests reach Nginx on the host | Check the Nginx container's ports |
| `sbomdelta-nginx` holds the current `frontend/dist` (same directory and `index.html` inodes inside and outside the container) | A publish must reach what Nginx serves | Reattach the mount ([Frontend bind mount](#frontend-bind-mount)) |
| `https://sbomdelta.website` through local Nginx serves `frontend/dist/index.html`, and `/api/repos` answers as [expected](#api-smoke-expectations) | The baseline for the post-deploy smoke tests | Fix the live site first |
| No Nginx `*.conf` changed since Nginx last loaded it | A reload must not apply unreviewed edits | Apply or revert the edit, then rerun |
| Containers were created from exactly `docker-compose.yml`, with no override file present | Deployments use exactly that file | Merge or remove the override |
| `com.docker.compose.config-hash` matches what root's Compose resolves | Recreating must change only the image | After a deliberate edit, apply it on the current image ([Changing the production configuration](#changing-the-production-configuration)); otherwise usually a different Compose version for root, or a variable that resolves differently; review |
| The running server has the sign-in settings and can read its client secret file | The new server refuses to start without them | [First deployment of dashboard sign-in](#first-deployment-of-dashboard-sign-in) |
| No service has `depends_on: {server: {restart: true}}` except the worker | Recreating the server must not restart Nginx | Remove `restart: true` |
| `/run/secrets` on the server is a bind mount with a `*.pem` key | Presence check for the GitHub App key | Set `GITHUB_APP_KEY_FILE` |

**Read-only checks**, in a Session Manager shell:

```bash
sudo -u ec2-user git -C /home/ec2-user/SBOMDelta-deploy remote -v
sudo -u ec2-user git -C /home/ec2-user/SBOMDelta-deploy status --short --untracked-files=no
sudo -u ec2-user git -C /home/ec2-user/SBOMDelta-deploy fetch --dry-run origin main && echo "fetch works"
sudo docker compose version
df -h /home/ec2-user "$(docker info --format '{{.DockerRootDir}}')"
```

### Overrides

`deploy.sh` reads these environment variables, with defaults matching
production: `PROD_DIR`, `PROD_COMPOSE_FILE`, `DEPLOY_DIR` (or `--deploy-dir`),
`BACKUP_DIR`, `DEPLOY_LOCK_FILE`, `FRONTEND_DIST`, `NGINX_CONTAINER`,
`NGINX_WEB_ROOT`, `PUBLIC_HOST`, `SERVER_SERVICE`, `WORKER_SERVICE`,
`POSTGRES_SERVICE`, `MINIO_SERVICE`, `NGINX_SERVICE`, `HEALTH_URL`, `GITHUB_APP_KEY_FILE`, `MIN_FREE_GB`,
`NODE_IMAGE`, `KEEP_BACKUPS` (default 10), `HEALTH_TIMEOUT`,
`DEPLOY_TIME_LIMIT`, `SWITCHOVER_RESERVE`.

## Rollback

**Automatic.** Any failure after the switchover, including a failed smoke test
through Nginx, restores the previous images and frontend, and the workflow
fails. The restored server must answer `/api/repos` the way its image
declares ([API smoke expectations](#api-smoke-expectations)).

**Redeploy an earlier commit.** This is the preferred way back. Run
**Actions → CD → Run workflow** with mode `deploy` and the earlier commit's
SHA (its CI must have passed). It rebuilds that commit and goes through every
check. `deploy-history.log` lists what was deployed when.

**Manual image rollback.** This is state-changing, so run it deliberately. The
previous release's images are kept under the tag `sbomdelta-rollback`, for the
release immediately before the last deployment only:

```bash
cd /home/ec2-user/SBOMDelta
P=$(docker ps --filter "label=com.docker.compose.project.working_dir=$PWD" \
      --format '{{.Label "com.docker.compose.project"}}' | sort -u)
for s in server worker; do
  ref=$(docker inspect --format '{{.Config.Image}}' "$(docker compose -f docker-compose.yml -p "$P" ps -q "$s")")
  docker tag "${ref%:*}:sbomdelta-rollback" "$ref"    # assumes a plain name; adjust for registry:port refs
done
docker compose --project-directory . -f docker-compose.yml -p "$P" up -d --no-deps --no-build server
curl -fsS http://127.0.0.1:8080/healthz
# The server may have a new address; Nginx resolves it again on a reload.
docker exec sbomdelta-nginx nginx -t && docker exec sbomdelta-nginx nginx -s reload
docker compose --project-directory . -f docker-compose.yml -p "$P" up -d --no-deps --no-build worker
tar -C frontend/dist -xzf /home/ec2-user/deployment-backups/frontend-dist-<timestamp>.tar.gz
```

**A worker that did not exist before.** If a deployment created the worker
and then failed, the new worker is left running the new image, which works
with the restored server (migrations are additive). If it must not run, stop
it (this keeps the container; it does not remove it):

```bash
cd /home/ec2-user/SBOMDelta
P=$(docker ps --filter "label=com.docker.compose.project.working_dir=$PWD" \
      --format '{{.Label "com.docker.compose.project"}}' | sort -u)
docker compose --project-directory . -f docker-compose.yml -p "$P" stop worker
```

**Database.** Migrations stay applied; the previous release works with them.
Restoring a dump with `pg_restore` **replaces current data**. It is a last
resort, to be decided explicitly, with the server and worker stopped first.

**Keep using the pipeline.** Running `docker compose up --build` by hand in
`/home/ec2-user/SBOMDelta` would rebuild the images from that directory's own
(older) source. Deploy through the workflow instead.

### Frontend bind mount

If preflight says the Nginx bind mount may reference a replaced copy of
`frontend/dist`, or a deployment failed with "sbomdelta-nginx does not see
the published index.html", Nginx is serving a directory that is no longer at
that path. Deployments write into the directory at the path, so they cannot
reach what visitors see. Reattaching means restarting the Nginx container,
which binds the path again. That is a short outage, so it is a deliberate
step: the deployment scripts never do it.

1. Confirm it, read-only, and compare what each side holds:
   ```bash
   pid=$(sudo docker inspect -f '{{.State.Pid}}' sbomdelta-nginx)
   sudo grep ' /usr/share/nginx/html ' /proc/$pid/mountinfo    # "//deleted": the old directory was removed
   stat -c '%i %n' /home/ec2-user/SBOMDelta/frontend/dist /home/ec2-user/SBOMDelta/frontend/dist/index.html
   sudo docker exec sbomdelta-nginx stat -c '%i %n' /usr/share/nginx/html /usr/share/nginx/html/index.html
   sha256sum /home/ec2-user/SBOMDelta/frontend/dist/index.html
   sudo docker exec sbomdelta-nginx sha256sum /usr/share/nginx/html/index.html
   ```
2. After the restart, visitors get what is in
   `/home/ec2-user/SBOMDelta/frontend/dist` on the host. If the two checksums
   differ, decide which content should be live before going on.
3. Check the configuration, then restart the container (a restart keeps its
   configuration and certificates; do not recreate or remove it):
   ```bash
   sudo docker exec sbomdelta-nginx nginx -t
   sudo docker restart sbomdelta-nginx
   ```
4. Check that the two `stat` commands from step 1 now print the same inode
   numbers, that the site answers, and then run the preflight again.

Find out what replaced the directory, and stop it: build or copy *into*
`frontend/dist`; never move, delete or re-create the directory itself.

## Changing the production configuration

Preflight requires each service to run exactly the configuration the
production `docker-compose.yml` and `.env` resolve to, so that a deployment
changes **only the image** and nothing nobody reviewed for it. A deliberate
configuration change is therefore its own step, done by hand **before** the
deployment: recreate the changed service on the image it already runs. That
proves the new configuration on its own, with the release that is known to
work, and records it in the container's `config-hash` label, which is what
preflight compares. Nothing about the check is relaxed.

This is state-changing: the server restarts (a few seconds of `502` through
Nginx). Run it deliberately, in a Session Manager shell, after editing only
the service you mean to change (here `server`):

<!-- config-apply:begin -->
```bash
cd /home/ec2-user/SBOMDelta
P=$(docker ps --filter "label=com.docker.compose.project.working_dir=$PWD" \
      --format '{{.Label "com.docker.compose.project"}}' | sort -u)
C="docker compose --project-directory . -f docker-compose.yml -p $P"
# 1. The image name must still mean the image the server runs now; stop if not.
cid=$($C ps -q server)
ref=$(docker inspect --format '{{.Config.Image}}' "$cid")
[ "$(docker inspect --format '{{.Image}}' "$cid")" = "$(docker image inspect --format '{{.Id}}' "$ref")" ] &&
  echo "server: $ref is the running image" || echo "STOP: $ref no longer names the running image"
# 2. Recreate only the server, on that image, with the new configuration.
$C up -d --no-deps --no-build server
curl -fsS http://127.0.0.1:8080/healthz
# 3. The server may have a new address; Nginx resolves it again on a reload.
docker exec sbomdelta-nginx nginx -t && docker exec sbomdelta-nginx nginx -s reload
curl -sS -o /dev/null -w '%{http_code}\n' https://sbomdelta.website/api/repos
```
<!-- config-apply:end -->

`--no-build` and `--no-deps` keep it to exactly that container and that
image; Nginx's reload changes nothing but the address it resolves (its
configuration on disk is the one it runs, which preflight also checks). If
`/healthz` is not `ok`, the new configuration is wrong for the current
release too: revert the edit and run the same commands again. Then run a CD
**preflight**; it must now pass the configuration check.

For the `worker`, run steps 1 and 2 with `worker` in place of `server`, and
skip the health check and the Nginx reload: the worker serves nothing. Then
check `$C ps worker` shows it running and `$C logs --tail 20 worker` shows
`worker started`.

## Tests

`deploy/tests/run-tests.sh` runs in CI (and locally on Linux or macOS). It
covers the bootstrap against throwaway git repositories (the lock refuses a
concurrent deployment without fetching or checking out, a commit off `main`
or a dirty checkout is refused, and the private copy, `--deploy-dir` and the
lock reach `deploy.sh`); the Nginx bind-mount identity check against real directories
(matching, a replaced directory with identical content, a different
`index.html`, a failing `docker exec` or `stat`); `deploy.sh`'s own backup,
publish and restore commands on a scratch frontend (same directory inode
throughout, `.well-known/` and other files kept, only stale assets pruned);
`deploy.sh`'s worker-image resolution against real
Compose files shaped like production (required in CI) and a Compose that
ignores service names; its container lookups against a stand-in
`docker` (worker absent, stopped, running or duplicated, one-off and
other-project containers ignored, strict single containers for the other
services, a Docker error never read as "absent"); the result-marker parser,
including truncated output;
redaction; the API smoke expectations (each expectation against the sign-in
refusal, a foreign 401, a 401 with another body, a repository list and other
failures, and an unknown or missing expectation accepting nothing); the
image sign-in label (on the server image only, read as `signin`, absent as
`repos`, anything else or an image that cannot be inspected an error, and the
same answer whatever state `current-sha` is in); old and new images through
preflight, the switch and rollback with `current-sha` missing, stale, garbage
and unreadable; the CD workflow's public check run as written against older
and signed-in commits and every reported `api=`;
the configuration-hash check (a configuration applied on the current image
passes, an unapplied edit stops with a pointer to the procedure) and that the
documented procedure keeps to `up -d --no-deps --no-build` with the same
Compose file and project as `deploy.sh`; the sign-in settings check run
against real files (missing settings, a wrong `PUBLIC_URL`, `AUTH_DISABLED`,
a missing, empty, unreadable or world-writable secret file, and no secret
ever printed); that the sign-in refusal is the same string in `deploy.sh`,
the CD workflow and the server's tests; and the destructive-command guard's
own cases.
`deploy/tests/check-destructive.sh` checks the deployment path itself.
`deploy.sh` needs root and Docker, so beyond ShellCheck it is exercised by its
own preflight.
