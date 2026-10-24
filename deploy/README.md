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
   answers, and `index.html` matches the build that was published.

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
  the production Compose file, skips the checks that need an existing worker
  (its current image and configuration hash), and a deployment creates the
  worker. With two or more, preflight fails and lists them;
- the images the services run are what the Compose file specifies;
- recreating `server` would not restart other services (no
  `depends_on: {server: {restart: true}}` outside the worker);
- the server and worker run the configuration Compose resolves now (their
  `com.docker.compose.config-hash` labels match `compose config --hash`), so
  recreating them changes only the image;
- the Postgres data volume exists; `.env` and the GitHub App key exist
  (checked for presence only, never read); Postgres is healthy;
- there is free disk for the backup and the image builds;
- `sbomdelta-nginx` serves exactly `/home/ec2-user/SBOMDelta/frontend/dist`,
  publishes port 443 on the host, passes `nginx -t`, and runs the
  configuration that is on disk (see [Nginx](#nginx));
- the site already works **through Nginx**: `https://sbomdelta.website/api/repos`
  answers with repositories and `/` is the current `index.html`. The requests
  go to Nginx on this host, so TLS, the server name and the proxying are all
  exercised;
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
changed, and then requires `/api/repos` to answer **through Nginx**.

**Worker.** Created, or recreated and started, only after that, and required
to run steadily without restarting. A worker that was stopped before the
deployment is started by it.

**Frontend.** Published into the bind-mounted `frontend/dist` **in place**:
assets first, `index.html` last, then stale files under `assets/` pruned. The
directory is never replaced (that would break the bind mount). Nothing outside
`assets/` is deleted, so `.well-known/` and any other files stay. The script
confirms the Nginx container sees the new `index.html`, then runs the final
smoke test through Nginx: `/api/repos` answers and `/` is the new build.

**Record.** The deployed commit goes to `current-sha` and
`deploy-history.log` in the backup directory, and the run prints its result
marker.

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

A reload applies whatever configuration is on disk, so preflight requires that
no `*.conf` file under `/etc/nginx` in the container changed after Nginx last
loaded its configuration (the start time of its oldest worker). An edit that
has not been applied, such as the planned `limit_except` change, stops the
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
  /healthz` on the server, read-only database queries, and `nginx -t`.

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

**Facts only the instance can confirm.** Preflight checks each of these and
stops if one does not hold. They cannot be verified from the repository,
because the production `docker-compose.yml` and `nginx/default.conf` exist
only on the instance:

| Requirement | Why | If it fails |
|---|---|---|
| The server answers at `http://127.0.0.1:8080/healthz` | The repository's development Compose file publishes `8080:8080`; the production file must too | Publish the port, or set `HEALTH_URL` |
| `sbomdelta-nginx` publishes 443/tcp on an IPv4 host address | The smoke tests reach Nginx on the host | Check the Nginx container's ports |
| `https://sbomdelta.website` through local Nginx serves `/api/repos` and `frontend/dist/index.html` | The baseline for the post-deploy smoke tests | Fix the live site first |
| No Nginx `*.conf` changed since Nginx last loaded it | A reload must not apply unreviewed edits | Apply or revert the edit, then rerun |
| Containers were created from exactly `docker-compose.yml`, with no override file present | Deployments use exactly that file | Merge or remove the override |
| `com.docker.compose.config-hash` matches what root's Compose resolves | Recreating must change only the image | Usually a different Compose version for root, or a variable that resolves differently; review |
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
fails.

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

## Tests

`deploy/tests/run-tests.sh` runs in CI (and locally on Linux or macOS). It
covers the bootstrap against throwaway git repositories (the lock refuses a
concurrent deployment without fetching or checking out, a commit off `main`
or a dirty checkout is refused, and the private copy, `--deploy-dir` and the
lock reach `deploy.sh`); `deploy.sh`'s container lookups against a stand-in
`docker` (worker absent, stopped, running or duplicated, one-off and
other-project containers ignored, strict single containers for the other
services, a Docker error never read as "absent"); the result-marker parser,
including truncated output;
redaction; and the destructive-command guard's own cases.
`deploy/tests/check-destructive.sh` checks the deployment path itself.
`deploy.sh` needs root and Docker, so beyond ShellCheck it is exercised by its
own preflight.
