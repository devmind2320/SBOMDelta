#!/usr/bin/env bash
# deploy.sh -- deploy one commit of SBOMDelta on the production EC2 host.
#
# deploy/bootstrap.sh runs this through AWS SSM, as root: it takes the host's
# deployment lock, checks out the commit in the deployment checkout, and runs a
# private copy of this file from that commit, which inherits the lock. Two
# directories are involved and they are deliberately kept apart:
#
#   DEPLOY_DIR  a clean git checkout used only as the *source* of the commit
#               being deployed: images and the frontend are built from it.
#   PROD_DIR    the production *runtime*: its Compose file, .env, secrets/,
#               Nginx configuration and the frontend/dist that Nginx serves.
#               Git is never run here, and nothing here is replaced except the
#               contents of frontend/dist.
#
# The script changes nothing until every preflight check has passed, and then
# proceeds in an order that keeps the site recoverable at each step: build new
# images and the frontend while the live services keep running, back up the
# database, switch the server (which applies migrations) and wait for it to be
# healthy directly and through Nginx, switch the worker, and only then publish
# the new frontend. A failure after the switch, including a failed smoke test
# through Nginx, restores the previous images and frontend automatically.
# Migrations are never rolled back; they are additive and the database backup
# taken beforehand is the recovery path.
#
# Nginx proxies to the server by its Compose service name, which Nginx resolves
# only when it loads its configuration. Recreating the server can give it a
# new address, so when that happens the script reloads Nginx gracefully (after
# `nginx -t`) so it resolves the name again. Preflight makes sure the
# configuration on disk is the one Nginx already runs, so a reload changes
# nothing else.
#
# It never removes containers, volumes or networks, never runs Compose without
# the production file and project name, and never prints environment values.
#
# Usage: deploy.sh --sha <40-char commit> --mode preflight|deploy
#                  [--deploy-dir DIR] [--skip-if-older] [--ci-override]
#
# A successful run ends with one result marker line, which the CD workflow
# requires (see deploy/ssm-result.sh):
#   SBOMDELTA_RESULT status=preflight-ok|skipped-older|deployed sha=... [...]

set -Eeuo pipefail
umask 077

PROD_DIR="${PROD_DIR:-/home/ec2-user/SBOMDelta}"
PROD_COMPOSE_FILE="${PROD_COMPOSE_FILE:-$PROD_DIR/docker-compose.yml}"
DEPLOY_DIR="${DEPLOY_DIR:-/home/ec2-user/SBOMDelta-deploy}"
BACKUP_DIR="${BACKUP_DIR:-/home/ec2-user/deployment-backups}"
LOCK_FILE="${DEPLOY_LOCK_FILE:-/run/lock/sbomdelta-deploy.lock}"
FRONTEND_DIST="${FRONTEND_DIST:-$PROD_DIR/frontend/dist}"
NGINX_CONTAINER="${NGINX_CONTAINER:-sbomdelta-nginx}"
NGINX_WEB_ROOT="${NGINX_WEB_ROOT:-/usr/share/nginx/html}"
PUBLIC_HOST="${PUBLIC_HOST:-sbomdelta.website}"
SERVER_SERVICE="${SERVER_SERVICE:-server}"
WORKER_SERVICE="${WORKER_SERVICE:-worker}"
POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
MINIO_SERVICE="${MINIO_SERVICE:-minio}"
NGINX_SERVICE="${NGINX_SERVICE:-nginx}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/healthz}"
GITHUB_APP_KEY_FILE="${GITHUB_APP_KEY_FILE:-}"
MIN_FREE_GB="${MIN_FREE_GB:-5}"
NODE_IMAGE="${NODE_IMAGE:-node:22-alpine}"
KEEP_BACKUPS="${KEEP_BACKUPS:-10}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"
# SSM stops the command after an hour. The script keeps inside its own limit,
# and refuses to start the switchover without enough time left to finish it
# or roll it back.
DEPLOY_TIME_LIMIT="${DEPLOY_TIME_LIMIT:-3300}"
SWITCHOVER_RESERVE="${SWITCHOVER_RESERVE:-900}"

SHA=""
MODE=""
SKIP_IF_OLDER=0
CI_OVERRIDE=0

# State consulted by the rollback handler.
PROJECT=""
SERVER_SWITCHED=0
WORKER_SWITCHED=0
# The worker, unlike the other services, may have no container: production can
# run without one, and a deployment then creates it.
WORKER_PRESENT=0
WORKER_STATE=""
FRONTEND_TOUCHED=0
FRONTEND_BACKUP=""
DB_BACKUP=""
ROLLING_BACK=0
# The server addresses Nginx resolved when it last loaded its configuration.
NGINX_UPSTREAM_IPS=""
# What the last smoke test found wrong, for the log; empty when it passed.
SMOKE_PROBLEM=""
# How /api/repos must answer an anonymous request through Nginx (see
# smoke_nginx): "signin" for a server image with dashboard sign-in, "repos" for
# one that predates it. It is always read from the image being checked (see
# image_api_expectation), never from deployment records.
API_EXPECT=""
# The expectation of the image the server ran before this deployment, which
# rollback restores, and of the image this deployment built.
PREVIOUS_API=""
NEW_API=""
# What the last smoke test saw /api/repos answer: signin, repos, or empty.
SMOKE_API_SEEN=""
# Preflight writes nothing to disk; the build log exists only in deploy mode.
BUILD_LOG=/dev/null

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

# REDACT_SED is deploy/redact.sed, verbatim; deploy/tests checks they match.
IFS= read -r -d '' REDACT_SED <<'REDACT_SED' || true
# redact.sed -- masks credential-shaped text in deployment output.
#
# Applied with `sed -E -f` by the CD workflow to everything the instance
# prints, and embedded verbatim in deploy.sh for the log excerpts it shows.
# deploy/tests/run-tests.sh checks that the two copies match. Keep it portable
# (GNU and BSD sed, no I flag): case-insensitive words are spelled out.
#
# Credentials in URLs: scheme://user:password@host
s#(://[^:/@[:space:]]+:)[^@[:space:]]+@#\1****@#g
# PEM private keys: a key on one line, then every line from BEGIN to END (or to
# the end of the output, if it was cut off).
s#-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*-----END [A-Z0-9 ]*PRIVATE KEY-----#[redacted private key]#g
/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,/-----END [A-Z0-9 ]*PRIVATE KEY-----/s#.*#[redacted private key]#
# Authorization headers, and bearer tokens anywhere.
s#([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]["']?[[:space:]]*[:=][[:space:]]*)[^",']+#\1****#g
s#([Bb][Ee][Aa][Rr][Ee][Rr][[:space:]]+)[A-Za-z0-9._~+/=-]+#\1****#g
# key=value and key: value, where the key names a credential.
s#([A-Za-z0-9_.-]*([Pp][Aa][Ss][Ss][Ww]([Oo][Rr])?[Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Kk][Ee][Yy]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll])[A-Za-z0-9_.-]*["']?[[:space:]]*[:=][[:space:]]*["']?)[^[:space:],"']+#\1****#g
# Well-known token formats, wherever they appear: GitHub, AWS access key IDs,
# Slack, JWTs, Google API keys, sk- style API keys, Stripe.
s#gh[pousr]_[A-Za-z0-9]{20,}#****#g
s#github_pat_[A-Za-z0-9_]{20,}#****#g
s#(AKIA|ASIA)[A-Z0-9]{16}#****#g
s#xox[abposr]-[A-Za-z0-9-]{10,}#****#g
s#eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}#****#g
s#AIza[0-9A-Za-z_-]{35}#****#g
s#sk-[A-Za-z0-9_-]{20,}#****#g
s#(sk|rk)_(live|test)_[0-9A-Za-z]{16,}#****#g
REDACT_SED
redact() { sed -E "$REDACT_SED"; }

usage() { die "usage: deploy.sh --sha <40-char commit> --mode preflight|deploy [--deploy-dir DIR] [--skip-if-older] [--ci-override]"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--sha) SHA="${2:-}"; shift 2 ;;
	--mode) MODE="${2:-}"; shift 2 ;;
	--deploy-dir) DEPLOY_DIR="${2:-}"; shift 2 ;;
	--skip-if-older) SKIP_IF_OLDER=1; shift ;;
	--ci-override) CI_OVERRIDE=1; shift ;;
	*) usage ;;
	esac
done
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$MODE" == preflight || "$MODE" == deploy ]] || usage
[[ "$DEPLOY_DIR" == /* ]] || usage

[ "$(id -u)" -eq 0 ] || die "must run as root (SSM runs it as root); it uses runuser to build as the checkout owner"

show_log_tail() {
	[ -f "$BUILD_LOG" ] || return 0
	log "last lines of $BUILD_LOG (redacted):"
	tail -n "${1:-40}" "$BUILD_LOG" | redact
}

# result prints the marker the CD workflow requires at the end of a run.
result() { printf 'SBOMDELTA_RESULT status=%s sha=%s%s\n' "$1" "$SHA" "${2:+ $2}"; }

# compose is the only way this script invokes Compose: always the production
# file, the production project directory (so its .env is used) and the project
# name read from the running containers. The repository's development
# docker-compose.yml is never consulted.
compose() {
	docker compose --project-directory "$PROD_DIR" -f "$PROD_COMPOSE_FILE" -p "$PROJECT" "$@"
}

# service_containers prints "ID NAME STATE" for each container of a production
# service, in any state. One-off `docker compose run` containers carry the
# service label too, and are left out.
service_containers() {
	docker ps -a --no-trunc \
		--filter "label=com.docker.compose.project=$PROJECT" \
		--filter "label=com.docker.compose.service=$1" \
		--filter "label=com.docker.compose.oneoff=False" \
		--format '{{.ID}} {{.Names}} {{.State}}'
}

# describe_containers turns service_containers lines into "name (state), ...".
describe_containers() {
	awk '{ printf "%s%s (%s)", (NR > 1 ? ", " : ""), $2, $3 } END { if (NR) print "" }'
}

# container_for prints the single container ID of a production service. It
# reports on stderr, because it is called inside command substitutions.
container_for() {
	local rows count
	rows="$(service_containers "$1")" || { log "ERROR: could not list containers for service '$1'" >&2; return 1; }
	count="$(printf '%s\n' "$rows" | grep -c . || true)"
	if [ "$count" -ne 1 ]; then
		log "ERROR: expected exactly one container for service '$1' in project '$PROJECT', found $count${rows:+: $(describe_containers <<<"$rows")}" >&2
		return 1
	fi
	printf '%s\n' "${rows%% *}"
}

# service_image prints the image Compose would use for one service. Naming a
# service in `compose config --images` also selects everything it depends on,
# so the worker's line comes with its dependencies' images. Its own image is
# what remains after removing the images of every other service. This prints
# nothing if the service shares its image with another service, or if another
# service depends on it; the caller requires exactly one line.
service_image() {
	local own others=() other_images service
	own="$(compose config --images "$1" 2>/dev/null)" || return 1
	while IFS= read -r service; do
		[ -z "$service" ] || [ "$service" = "$1" ] || others+=("$service")
	done < <(compose config --services 2>/dev/null)
	other_images=""
	if [ "${#others[@]}" -gt 0 ]; then
		other_images="$(compose config --images "${others[@]}" 2>/dev/null)" || return 1
	fi
	comm -23 <(printf '%s\n' "$own" | grep . | sort -u) <(printf '%s\n' "$other_images" | grep . | sort -u)
}

# resolve_worker sets WORKER_PRESENT, WORKER_CID and WORKER_STATE. No worker
# container is a valid state; several are not, since guessing which one is
# production is unsafe.
resolve_worker() {
	local rows count
	rows="$(service_containers "$WORKER_SERVICE")" || { log "ERROR: could not list containers for service '$WORKER_SERVICE'" >&2; return 1; }
	count="$(printf '%s\n' "$rows" | grep -c . || true)"
	case "$count" in
	0) WORKER_PRESENT=0; WORKER_CID=""; WORKER_STATE=absent ;;
	1) WORKER_PRESENT=1; read -r WORKER_CID _ WORKER_STATE <<<"$rows" ;;
	*)
		log "ERROR: expected at most one container for service '$WORKER_SERVICE' in project '$PROJECT', found $count: $(describe_containers <<<"$rows")" >&2
		return 1
		;;
	esac
}

# container_ips prints a container's addresses on all its networks, sorted.
container_ips() {
	docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" |
		tr ' ' '\n' | grep . | sort | tr '\n' ' '
}

# mount_source prints the host source of a container mount at a destination.
mount_source() {
	docker inspect --format \
		'{{range .Mounts}}{{if eq .Destination "'"$2"'"}}{{.Type}} {{if .Name}}{{.Name}}{{else}}{{.Source}}{{end}}{{end}}{{end}}' "$1"
}

# dist_mount_matches checks that Nginx's web root is the very directory this
# script updates, not merely the same path. Docker binds the directory that
# existed when the container started; if frontend/dist was replaced since
# (moved aside, re-created, copied over), Nginx keeps serving the old one and
# a publish lands where it cannot see it. The directory and index.html must
# have the same inode numbers on the host and inside the container. Read-only;
# any failure to read them counts as a mismatch.
dist_mount_matches() {
	local host_dir host_index nginx_dir nginx_index
	host_dir="$(stat -c %i "$FRONTEND_DIST" 2>/dev/null)" || host_dir=""
	host_index="$(stat -c %i "$FRONTEND_DIST/index.html" 2>/dev/null)" || host_index=""
	nginx_dir="$(docker exec "$NGINX_CONTAINER" stat -c %i "$NGINX_WEB_ROOT" 2>/dev/null)" || nginx_dir=""
	nginx_index="$(docker exec "$NGINX_CONTAINER" stat -c %i "$NGINX_WEB_ROOT/index.html" 2>/dev/null)" || nginx_index=""
	if ! [[ "$host_dir" =~ ^[0-9]+$ && "$host_index" =~ ^[0-9]+$ && "$nginx_dir" =~ ^[0-9]+$ && "$nginx_index" =~ ^[0-9]+$ ]]; then
		log "ERROR: could not read the inodes of $FRONTEND_DIST and $NGINX_CONTAINER:$NGINX_WEB_ROOT (and their index.html)" >&2
		return 1
	fi
	if [ "$host_dir" != "$nginx_dir" ]; then
		log "ERROR: $FRONTEND_DIST is inode $host_dir on the host, but $NGINX_CONTAINER sees inode $nginx_dir at $NGINX_WEB_ROOT" >&2
		return 1
	fi
	if [ "$host_index" != "$nginx_index" ]; then
		log "ERROR: $FRONTEND_DIST/index.html is inode $host_index on the host, but $NGINX_CONTAINER sees inode $nginx_index" >&2
		return 1
	fi
}

# psql_ro runs one read-only query in the Postgres container. The connection
# settings are the container's own and are expanded inside it, never here.
psql_ro() {
	docker exec -i \
		-e PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=30s' \
		"$PG_CID" sh -c 'u="${POSTGRES_USER:-postgres}"; exec psql -X -qtA -v ON_ERROR_STOP=1 -U "$u" -d "${POSTGRES_DB:-$u}"' \
		<<<"$1"
}

# image_repo strips a tag, keeping any registry port: host:5000/app:tag -> host:5000/app.
image_repo() {
	local ref="$1" last="${1##*/}"
	if [[ "$last" == *:* ]]; then printf '%s\n' "${ref%:*}"; else printf '%s\n' "$ref"; fi
}

normalize_ref() {
	local last="${1##*/}"
	if [[ "$last" == *:* ]]; then printf '%s\n' "$1"; else printf '%s:latest\n' "$1"; fi
}

# free_gb reports free space for a path, or for its nearest existing parent.
free_gb() {
	local path="$1"
	while [ ! -e "$path" ]; do path="$(dirname "$path")"; done
	df -BG --output=avail "$path" | tail -n 1 | tr -dc '0-9'
}

time_left() { printf '%s\n' "$((DEPLOY_TIME_LIMIT - SECONDS))"; }

require_time() {
	[ "$(time_left)" -ge "$1" ] ||
		die "only $(time_left)s left of the ${DEPLOY_TIME_LIMIT}s limit; not starting $2"
}

# bounded runs an external command with a timeout that still leaves the
# switchover reserve, so a slow build fails before anything live has changed.
bounded() {
	local budget=$(($(time_left) - SWITCHOVER_RESERVE))
	[ "$budget" -gt 60 ] || { log "no time left for: $1"; return 124; }
	timeout --kill-after=30 "$budget" "$@"
}

wait_for_health() {
	local deadline=$((SECONDS + HEALTH_TIMEOUT)) body
	while [ "$SECONDS" -lt "$deadline" ]; do
		body="$(curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null || true)"
		if [[ "$body" == *'"status":"ok"'* ]]; then
			return 0
		fi
		sleep 3
	done
	return 1
}

# wait_for_container waits until a service has run the expected image for
# three consecutive checks (about ten seconds) without restarting, which is
# what separates a started container from one in a crash loop.
wait_for_container() {
	local service="$1" image_id="$2" cid="" state steady=0 i
	for i in $(seq 1 12); do
		if cid="$(container_for "$service")"; then
			state="$(docker inspect --format '{{.Image}} {{.State.Status}} {{.RestartCount}}' "$cid")"
		else
			state=""
		fi
		if [ "$state" = "$image_id running 0" ]; then
			steady=$((steady + 1))
			[ "$steady" -ge 3 ] && return 0
		else
			steady=0
		fi
		sleep 5
	done
	log "$service state after $i checks: $(docker inspect --format '{{.State.Status}} restarts={{.RestartCount}}' "$cid" 2>/dev/null)"
	return 1
}

# nginx_get fetches a path through the running Nginx, exactly as a visitor's
# request would arrive (TLS, server name, proxying), without leaving the host.
# It writes the body to a file and prints the HTTP status.
nginx_get() {
	curl -sS -o "$2" -w '%{http_code}' --max-time 10 \
		--resolve "$PUBLIC_HOST:$NGINX_HTTPS_PORT:$NGINX_HTTPS_IP" \
		"https://$PUBLIC_HOST:$NGINX_HTTPS_PORT$1" 2>/dev/null || true
}

# SIGNIN_REFUSAL is the server's exact answer to an anonymous /api request
# (auth.RequireUser). Only this body counts: any other 401 -- from Nginx, a
# load balancer, or another application -- proves nothing about this server.
SIGNIN_REFUSAL='{"error":"authentication required"}'

# smoke_nginx checks the API through Nginx and, given a checksum, that Nginx
# serves that index.html. On failure SMOKE_PROBLEM says which check failed --
# the API, the homepage's status, or its checksum -- since each points at a
# different fault. Bodies are never printed; status codes and checksums are.
#
# API_EXPECT says how an anonymous /api/repos must answer: "signin" (the
# server's own JSON 401, and nothing else) or "repos" (a server that predates
# sign-in lists repositories). Anything else, including no expectation at
# all, fails. A server with sign-in that lists repositories anonymously fails
# "signin": that is an authorization failure.
smoke_nginx() {
	local body code sha
	SMOKE_PROBLEM=""
	SMOKE_API_SEEN=""
	case "$API_EXPECT" in
	signin | repos) ;;
	*)
		SMOKE_PROBLEM="unknown API expectation '$API_EXPECT'"
		return 1
		;;
	esac
	body="$(mktemp)"
	code="$(nginx_get /api/repos "$body")"
	if [ "$code" = 401 ] && [ "$(tr -d '\r\n' <"$body")" = "$SIGNIN_REFUSAL" ]; then
		SMOKE_API_SEEN=signin
	elif [ "$code" = 200 ] && grep -q '"repositories"' "$body"; then
		SMOKE_API_SEEN=repos
	fi
	case "$API_EXPECT:$SMOKE_API_SEEN" in
	signin:signin | repos:repos) ;;
	signin:repos)
		SMOKE_PROBLEM="/api/repos listed repositories without sign-in (HTTP 200); this server must refuse anonymous requests" ;;
	repos:signin)
		SMOKE_PROBLEM="/api/repos required sign-in, but the server checked here predates it" ;;
	*:)
		if [ "$code" = 401 ]; then
			SMOKE_PROBLEM="/api/repos returned 401 without the server's sign-in response"
		elif [ "$code" != 200 ]; then
			SMOKE_PROBLEM="/api/repos returned HTTP ${code:-none}"
		else
			SMOKE_PROBLEM="/api/repos returned 200 without a repositories list"
		fi
		;;
	esac
	if [ -z "$SMOKE_PROBLEM" ] && [ -n "${1:-}" ]; then
		code="$(nginx_get / "$body")"
		if [ "$code" != 200 ]; then
			SMOKE_PROBLEM="the homepage (/) returned HTTP ${code:-none}"
		else
			sha="$(sha256sum <"$body" | cut -d' ' -f1)"
			[ "$sha" = "$1" ] || SMOKE_PROBLEM="the homepage (/) served index.html sha256 $sha, expected $1"
		fi
	fi
	rm -f -- "$body"
	[ -z "$SMOKE_PROBLEM" ]
}

# SIGNIN_LABEL is set on the server image by backend/Dockerfile from the
# release that added dashboard sign-in. It travels with the image, so it says
# what a server will do whichever image is running -- the current one, the
# rollback image, or a new build -- and no host file can make it stale.
SIGNIN_LABEL=org.sbomdelta.dashboard-signin

# image_api_expectation <image> prints how a server from that image must
# answer an anonymous /api/repos: "signin" when the image declares
# SIGNIN_LABEL=required, "repos" when it has no such label (it predates sign-in
# and lists repositories anonymously). Any other value, or an image that
# cannot be inspected, is an error: guessing could accept an open API.
image_api_expectation() {
	local label
	if ! label="$(docker image inspect --format "{{index .Config.Labels \"$SIGNIN_LABEL\"}}" "$1" 2>/dev/null)"; then
		log "ERROR: could not read the labels of image $1" >&2
		return 1
	fi
	case "$label" in
	required) echo signin ;;
	"" | "<no value>") echo repos ;;
	*)
		log "ERROR: image $1 has an unrecognized $SIGNIN_LABEL label" >&2
		return 1
		;;
	esac
}

wait_for_nginx() {
	local i
	for i in $(seq 1 10); do
		smoke_nginx "${1:-}" && return 0
		sleep 3
	done
	log "Nginx smoke test failed $i times; last: $SMOKE_PROBLEM"
	return 1
}

# refresh_nginx_upstream reloads Nginx gracefully if the server's address has
# changed since Nginx last resolved it; otherwise it leaves Nginx alone.
refresh_nginx_upstream() {
	local cid ips
	cid="$(container_for "$SERVER_SERVICE")" || return 1
	ips="$(container_ips "$cid")"
	if [ "$ips" = "$NGINX_UPSTREAM_IPS" ]; then
		log "ok: server address unchanged ($ips); Nginx needs no reload"
		return 0
	fi
	log "server address changed (${NGINX_UPSTREAM_IPS}-> $ips); reloading Nginx gracefully so it resolves '$SERVER_SERVICE' again"
	docker exec "$NGINX_CONTAINER" nginx -t >>"$BUILD_LOG" 2>&1 || { log "nginx -t failed; Nginx was not reloaded"; return 1; }
	docker exec "$NGINX_CONTAINER" nginx -s reload >>"$BUILD_LOG" 2>&1 || { log "nginx -s reload failed"; return 1; }
	NGINX_UPSTREAM_IPS="$ips"
}

# check_signin_settings <server container> <public origin> checks, before
# anything changes, that the running server already has what the new server
# needs to start: the dashboard sign-in settings, applied beforehand on the
# current image (deploy/README.md, "Changing the production configuration"),
# and a client secret file the server's own user can read. The check runs
# inside the container, as the image's user and through its real mounts, and
# prints only setting names, the secret's path and the user's uid -- never a
# value from the environment and never the secret.
# shellcheck disable=SC2016 # expanded inside the container, on purpose
SIGNIN_CHECK_SCRIPT='
[ -n "${GITHUB_CLIENT_ID:-}" ] || echo "problem: GITHUB_CLIENT_ID is not set"
[ -n "${ALLOWED_GITHUB_LOGINS:-}" ] || echo "problem: ALLOWED_GITHUB_LOGINS is not set"
if [ -z "${PUBLIC_URL:-}" ]; then
	echo "problem: PUBLIC_URL is not set"
elif [ "$PUBLIC_URL" != "$1" ] && [ "$PUBLIC_URL" != "$1/" ]; then
	echo "problem: PUBLIC_URL is not $1"
fi
case "${AUTH_DISABLED:-}" in
1 | t | T | true | TRUE | True) echo "problem: AUTH_DISABLED is set; production must not disable sign-in" ;;
esac
secret="${GITHUB_CLIENT_SECRET_PATH:-}"
if [ -n "${GITHUB_CLIENT_SECRET:-}" ]; then
	echo "ok: client secret given inline"
elif [ -z "$secret" ]; then
	echo "problem: neither GITHUB_CLIENT_SECRET_PATH nor GITHUB_CLIENT_SECRET is set"
elif [ ! -e "$secret" ]; then
	echo "problem: the client secret file $secret does not exist in the server container"
elif [ ! -f "$secret" ]; then
	echo "problem: the client secret path $secret is not a regular file"
elif [ ! -r "$secret" ]; then
	echo "problem: the client secret file $secret is not readable by the server user (uid $(id -u))"
elif ! grep -q "[^[:space:]]" "$secret" 2>/dev/null; then
	echo "problem: the client secret file $secret is empty"
else
	echo "ok: client secret file $secret is readable by the server user (uid $(id -u))"
	if [ -n "$(find "$secret" -prune -perm -0002 2>/dev/null)" ]; then
		echo "problem: the client secret file $secret is writable by everyone"
	elif [ -n "$(find "$secret" -prune -perm -0004 2>/dev/null)" ]; then
		echo "warn: the client secret file $secret is readable by everyone; mode 0400 owned by uid $(id -u) is enough"
	fi
fi
'
check_signin_settings() {
	local report line problems=0 secret_ok=0
	report="$(docker exec "$1" sh -c "$SIGNIN_CHECK_SCRIPT" sh "$2" 2>/dev/null)" || report=""
	if [ -z "$report" ]; then
		log "ERROR: could not check the dashboard sign-in settings inside the server container"
		return 1
	fi
	while IFS= read -r line; do
		case "$line" in
		"problem: "*) log "ERROR: ${line#problem: }"; problems=$((problems + 1)) ;;
		"warn: "*) log "WARNING: ${line#warn: }" ;;
		"ok: "*) log "${line}"; secret_ok=1 ;;
		esac
	done <<<"$report"
	if [ "$problems" -gt 0 ] || [ "$secret_ok" -ne 1 ]; then
		log "ERROR: the new server would refuse to start. Add the dashboard sign-in settings to the server service and apply them on the current image first (deploy/README.md, \"Changing the production configuration\"). Nothing was changed."
		return 1
	fi
	log "ok: dashboard sign-in settings present in the running server"
}

# ---------------------------------------------------------------- rollback --

rollback() {
	set +e
	trap '' TERM INT HUP
	ROLLING_BACK=1
	# The restored server is the image the server ran before, so it must answer
	# /api/repos the way that image does. Preflight read that from the image
	# before anything was switched; without it, no answer is accepted.
	API_EXPECT="${PREVIOUS_API:-unknown}"
	log "ROLLBACK: restoring the previous release"
	local restored_sha=""
	if [ "$FRONTEND_TOUCHED" -eq 1 ] && [ -n "$FRONTEND_BACKUP" ]; then
		if as_dist_owner tar -C "$FRONTEND_DIST" -xzf - <"$FRONTEND_BACKUP"; then
			log "ROLLBACK: frontend restored from $FRONTEND_BACKUP"
			# The backup's recorded modes may themselves be too narrow.
			make_dist_readable || log "ROLLBACK: could not make the restored frontend readable by Nginx; check the modes under $FRONTEND_DIST"
			restored_sha="$(sha256sum "$FRONTEND_DIST/index.html" | cut -d' ' -f1)"
		else
			log "ROLLBACK: frontend restore FAILED; restore $FRONTEND_BACKUP by hand"
		fi
	fi
	if [ "$WORKER_SWITCHED" -eq 1 ] && [ "$WORKER_PRESENT" -eq 0 ]; then
		# There is no previous worker to go back to, and this script never stops
		# or removes containers. The new worker stays; it works with the
		# restored server, because migrations are additive.
		log "ROLLBACK: '$WORKER_SERVICE' had no container before this deployment, so it is left on the new image."
		log "ROLLBACK: if it must not run, stop it by hand (deploy/README.md, Rollback, \"worker that did not exist before\")"
	elif [ "$WORKER_SWITCHED" -eq 1 ]; then
		# Put the previous image back in the state it was in: running, or not.
		start_flag=-d
		[ "$WORKER_STATE" = running ] || start_flag=--no-start
		if docker tag "$WORKER_REPO:sbomdelta-rollback" "$WORKER_REF" &&
			compose up "$start_flag" --no-deps --no-build "$WORKER_SERVICE" >>"$BUILD_LOG" 2>&1; then
			log "ROLLBACK: worker back on its previous image (previously $WORKER_STATE)"
		else
			log "ROLLBACK: worker restore FAILED"
		fi
	fi
	if [ "$SERVER_SWITCHED" -eq 1 ]; then
		if docker tag "$SERVER_REPO:sbomdelta-rollback" "$SERVER_REF" &&
			compose up -d --no-deps --no-build "$SERVER_SERVICE" >>"$BUILD_LOG" 2>&1; then
			log "ROLLBACK: server back on its previous image"
		else
			log "ROLLBACK: server restore FAILED"
		fi
		if wait_for_health; then
			log "ROLLBACK: previous server is healthy"
		else
			log "ROLLBACK: previous server did NOT become healthy; investigate immediately"
		fi
		if ! refresh_nginx_upstream; then
			log "ROLLBACK: Nginx could not be pointed at the restored server; investigate immediately"
		fi
		log "ROLLBACK: database migrations are not reverted; pre-deploy backup: $DB_BACKUP"
	fi
	# With the frontend restored, / must serve the restored index.html, not
	# merely answer: the API alone says nothing about what visitors get. If
	# the frontend was touched but not restored, there is nothing to verify
	# the homepage against, and the log must not suggest that it was.
	if [ "$FRONTEND_TOUCHED" -eq 1 ] && [ -z "$restored_sha" ]; then
		if wait_for_nginx; then
			log "ROLLBACK: /api/repos answers through Nginx, but the frontend was NOT restored, so the homepage is UNVERIFIED; restore ${FRONTEND_BACKUP:-the frontend} by hand"
		else
			log "ROLLBACK: the site does NOT answer through Nginx, and the frontend was NOT restored; investigate immediately"
		fi
	elif wait_for_nginx "$restored_sha"; then
		log "ROLLBACK: the site answers through Nginx${restored_sha:+ and serves the restored index.html}"
	else
		log "ROLLBACK: the site does NOT answer through Nginx; investigate immediately"
	fi
}

on_exit() {
	local code=$?
	if [ "$code" -ne 0 ]; then
		show_log_tail 30
		if [ "$ROLLING_BACK" -eq 0 ] &&
			{ [ "$SERVER_SWITCHED" -eq 1 ] || [ "$WORKER_SWITCHED" -eq 1 ] || [ "$FRONTEND_TOUCHED" -eq 1 ]; }; then
			rollback
		fi
		log "$MODE of ${SHA:0:12} FAILED (exit $code)"
	fi
	# bootstrap.sh runs a private copy of this script; remove it, and only it.
	if [ -n "${DEPLOY_SCRIPT_COPY:-}" ] && [ "$DEPLOY_SCRIPT_COPY" = "${BASH_SOURCE[0]}" ]; then
		rm -f -- "$DEPLOY_SCRIPT_COPY"
		rmdir -- "$(dirname "$DEPLOY_SCRIPT_COPY")" 2>/dev/null || true
	fi
	exit "$code"
}
trap on_exit EXIT

# SSM stops a command that outlives its timeout, and an operator can cancel
# it. Turn those signals into a failing exit so the rollback above still runs.
# This is best effort: a signal arrives only between commands, and nothing
# can catch SIGKILL. The time limit is what keeps the switchover clear of it.
on_signal() {
	log "received SIG$1"
	exit "$2"
}
trap 'on_signal TERM 143' TERM
trap 'on_signal INT 130' INT
trap 'on_signal HUP 129' HUP

# One deployment at a time on this host. bootstrap.sh takes this lock before
# it touches the checkout and passes it down on descriptor 9; locking that same
# descriptor again succeeds. Run by hand, the script takes the lock itself.
if [ -e "/proc/$$/fd/9" ] && [ "$(readlink -f "/proc/$$/fd/9")" = "$(readlink -f "$LOCK_FILE")" ]; then
	flock -n 9 || die "the deployment lock $LOCK_FILE is not held"
else
	exec 9>>"$LOCK_FILE"
	flock -n 9 || die "another deployment holds $LOCK_FILE"
fi

BUILD_USER="$(stat -c %U "$DEPLOY_DIR" 2>/dev/null)" || die "deployment checkout $DEPLOY_DIR does not exist"
BUILD_HOME="$(getent passwd "$BUILD_USER" | cut -d: -f6)"
BUILD_UID="$(id -u "$BUILD_USER")"
BUILD_GID="$(id -g "$BUILD_USER")"

as_build_user() { runuser -u "$BUILD_USER" -- env HOME="$BUILD_HOME" "$@"; }

# --------------------------------------------------------------- preflight --
# Read-only. Nothing on the host changes in this phase: services, Nginx and
# the database are only inspected, and nothing is written except short-lived
# private temporary files for the smoke-test responses (no build log, no
# backup directory).

log "SBOMDelta $MODE for ${SHA:0:12}"
log "preflight: nothing is changed until every check passes"

for tool in docker git curl tar gzip find df flock runuser sha256sum cmp comm stat getent readlink timeout install mktemp; do
	command -v "$tool" >/dev/null || die "required tool '$tool' is not installed"
done
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is not available to root"

# The source checkout must be exactly the commit requested, unmodified, and
# this script must be that commit's deploy/deploy.sh.
[ "$(as_build_user git -C "$DEPLOY_DIR" rev-parse HEAD)" = "$SHA" ] ||
	die "$DEPLOY_DIR is not checked out at $SHA"
[ -z "$(as_build_user git -C "$DEPLOY_DIR" status --porcelain --untracked-files=no)" ] ||
	die "$DEPLOY_DIR has local modifications to tracked files"
as_build_user git -C "$DEPLOY_DIR" show "$SHA:deploy/deploy.sh" | cmp -s - "${BASH_SOURCE[0]}" ||
	die "this script is not deploy/deploy.sh from ${SHA:0:12}"
log "ok: source checkout $DEPLOY_DIR is at ${SHA:0:12} and clean"

if [ "$SKIP_IF_OLDER" -eq 1 ] && [ -s "$BACKUP_DIR/current-sha" ]; then
	current="$(cat "$BACKUP_DIR/current-sha")"
	if [ "$current" != "$SHA" ] &&
		as_build_user git -C "$DEPLOY_DIR" merge-base --is-ancestor "$SHA" "$current" 2>/dev/null; then
		log "skipping: ${SHA:0:12} is older than the deployed ${current:0:12}"
		result skipped-older "deployed=$current"
		exit 0
	fi
fi

# The production Compose file must exist and must not be the repository's.
[ -f "$PROD_COMPOSE_FILE" ] || die "production Compose file $PROD_COMPOSE_FILE not found"
PROD_DIR_REAL="$(realpath "$PROD_DIR")"
PROD_COMPOSE_REAL="$(realpath "$PROD_COMPOSE_FILE")"
DEPLOY_DIR_REAL="$(realpath "$DEPLOY_DIR")"
case "$PROD_COMPOSE_REAL" in
"$DEPLOY_DIR_REAL"/*) die "refusing a Compose file inside the deployment checkout: $PROD_COMPOSE_REAL" ;;
esac
[ "$PROD_DIR_REAL" != "$DEPLOY_DIR_REAL" ] || die "PROD_DIR and DEPLOY_DIR must be different directories"
# A plain `docker compose` in PROD_DIR would merge an override file, while this
# script uses exactly one file. Refuse the ambiguity instead of ignoring it.
for override in docker-compose.override.yml docker-compose.override.yaml compose.override.yml compose.override.yaml; do
	[ ! -e "$PROD_DIR_REAL/$override" ] ||
		die "$PROD_DIR_REAL/$override exists; deployments use exactly $PROD_COMPOSE_REAL, so merge or remove the override first"
done
log "ok: production Compose file $PROD_COMPOSE_REAL"

# The project name comes from the running containers, never from a guess.
mapfile -t projects < <(docker ps -a \
	--filter "label=com.docker.compose.project.working_dir=$PROD_DIR_REAL" \
	--format '{{.Label "com.docker.compose.project"}}' | sort -u | grep .)
[ "${#projects[@]}" -eq 1 ] ||
	die "expected one Compose project with working dir $PROD_DIR_REAL, found ${#projects[@]}"
PROJECT="${projects[0]}"
# Every container must have been created from exactly the production file:
# no extra -f files and no override.
while IFS= read -r files; do
	if [[ "$files" == *,* ]] || [ "$(realpath -e "$files" 2>/dev/null)" != "$PROD_COMPOSE_REAL" ]; then
		die "project '$PROJECT' has containers created from '$files', not exactly $PROD_COMPOSE_REAL"
	fi
done < <(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
	--format '{{.Label "com.docker.compose.project.config_files"}}' | sort -u)
log "ok: Compose project '$PROJECT' (from container labels), created from that file alone"

services="$(compose config --services 2>/dev/null)" || die "the production Compose file does not parse"
for service in "$SERVER_SERVICE" "$WORKER_SERVICE" "$POSTGRES_SERVICE" "$MINIO_SERVICE" "$NGINX_SERVICE"; do
	grep -qx "$service" <<<"$services" || die "service '$service' is not defined in the production Compose file"
done
compose_images="$(compose config --images 2>/dev/null)" || die "could not list production images"

# Every service but the worker must have exactly one container.
SERVER_CID="$(container_for "$SERVER_SERVICE")" || die "cannot identify the server container"
PG_CID="$(container_for "$POSTGRES_SERVICE")" || die "cannot identify the Postgres container"
MINIO_CID="$(container_for "$MINIO_SERVICE")" || die "cannot identify the MinIO container"
[ "$(docker inspect --format '{{.State.Status}}' "$MINIO_CID")" = running ] || die "MinIO is not running"
NGINX_CID="$(container_for "$NGINX_SERVICE")" || die "cannot identify the Nginx container"
[ "$(docker inspect --format '{{.Id}}' "$NGINX_CONTAINER" 2>/dev/null)" = "$NGINX_CID" ] ||
	die "$NGINX_CONTAINER is not the '$NGINX_SERVICE' container of project '$PROJECT'"
resolve_worker || die "cannot identify the worker container"

# Images: the name Compose will run, and the image each service runs now. With
# no worker container, the worker's image name comes from the production
# Compose file, and there is no previous worker image.
SERVER_REF="$(docker inspect --format '{{.Config.Image}}' "$SERVER_CID")"
SERVER_OLD_ID="$(docker inspect --format '{{.Image}}' "$SERVER_CID")"
if [ "$WORKER_PRESENT" -eq 1 ]; then
	WORKER_REF="$(docker inspect --format '{{.Config.Image}}' "$WORKER_CID")"
	WORKER_OLD_ID="$(docker inspect --format '{{.Image}}' "$WORKER_CID")"
	log "ok: '$WORKER_SERVICE' container is $WORKER_STATE"
else
	WORKER_REF="$(service_image "$WORKER_SERVICE")" ||
		die "could not resolve the '$WORKER_SERVICE' image from the production Compose file"
	[ "$(printf '%s\n' "$WORKER_REF" | grep -c . || true)" -eq 1 ] ||
		die "the production Compose file does not resolve to exactly one image for '$WORKER_SERVICE'"
	WORKER_OLD_ID=""
	log "note: '$WORKER_SERVICE' has no container; a deployment will create it from $WORKER_REF once the new server is healthy"
fi
for ref in "$SERVER_REF" "$WORKER_REF"; do
	[[ "$ref" != sha256:* ]] || die "a running service uses an untagged image; cannot redeploy it safely"
	normalized="$(normalize_ref "$ref")"
	while IFS= read -r image; do
		[ "$(normalize_ref "$image")" = "$normalized" ] && continue 2
	done <<<"$compose_images"
	die "running image $ref is not what the production Compose file now specifies"
done
[ "$(normalize_ref "$SERVER_REF")" != "$(normalize_ref "$WORKER_REF")" ] ||
	die "server and worker share the image $SERVER_REF; retagging one would move the other"
SERVER_REPO="$(image_repo "$SERVER_REF")"
WORKER_REPO="$(image_repo "$WORKER_REF")"
log "ok: service images $SERVER_REF and $WORKER_REF"

# Recreating server and worker must not drag other services along: Compose
# restarts a service that declares `depends_on: {server: {restart: true}}`.
# The label records each dependency as service:condition:restart.
while IFS=' ' read -r dependent deps; do
	[ "$dependent" = "$WORKER_SERVICE" ] && continue
	IFS=',' read -ra entries <<<"$deps"
	for entry in "${entries[@]}"; do
		case "$entry" in
		"$SERVER_SERVICE":*:true | "$WORKER_SERVICE":*:true)
			die "service '$dependent' would be restarted when '${entry%%:*}' is recreated (depends_on restart: true)" ;;
		esac
	done
done < <(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
	--format '{{.Label "com.docker.compose.service"}} {{.Label "com.docker.compose.depends_on"}}')

# Compose must see the same service configuration the containers run, or
# recreating them would also change their environment, ports or mounts (for
# example if root's Compose differs from the one that started production, or
# a variable resolves differently). Only hashes are compared, never printed
# configuration.
#
# A deliberate configuration change -- such as the dashboard sign-in settings
# -- is therefore applied on its own first, by recreating the service on the
# image it already runs (deploy/README.md, "Changing the production
# configuration"). The deployment then changes only the image, as this check
# requires.
check_config_hash() {
	local service cid running_hash running_version wanted_hash compose_version
	compose_version="$(docker compose version --short 2>/dev/null || true)"
	for service in "$@"; do
		cid="$(container_for "$service")" || { log "ERROR: cannot identify the $service container"; return 1; }
		running_hash="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$cid")"
		running_version="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.version"}}' "$cid")"
		wanted_hash="$(compose config --hash "$service" 2>/dev/null | awk '{print $NF}')"
		if [ -z "$wanted_hash" ] || [ "$running_hash" != "$wanted_hash" ]; then
			log "ERROR: '$service' runs a different configuration than the production Compose file resolves to now (Compose $compose_version here, $running_version created it)."
			log "ERROR: if you changed that file or .env on purpose, apply the change on the current image first (deploy/README.md, \"Changing the production configuration\"); otherwise review the difference. Nothing was changed."
			return 1
		fi
	done
	log "ok: $* run the configuration Compose resolves (Compose $compose_version)"
}
hash_services=("$SERVER_SERVICE")
[ "$WORKER_PRESENT" -eq 0 ] || hash_services+=("$WORKER_SERVICE")
check_config_hash "${hash_services[@]}" || exit 1

# Persistent database storage must already exist.
read -r pg_type pg_volume <<<"$(mount_source "$PG_CID" /var/lib/postgresql/data)"
case "$pg_type" in
volume) docker volume inspect "$pg_volume" >/dev/null 2>&1 || die "database volume $pg_volume is missing" ;;
bind) [ -d "$pg_volume" ] || die "database directory $pg_volume is missing" ;;
*) die "Postgres has no persistent mount at /var/lib/postgresql/data" ;;
esac
log "ok: database storage $pg_type $pg_volume"

# Secrets exist. Only their presence is checked; nothing is read.
[ -s "$PROD_DIR/.env" ] || die "$PROD_DIR/.env is missing or empty"
if [ -z "$GITHUB_APP_KEY_FILE" ]; then
	read -r secrets_type secrets_dir <<<"$(mount_source "$SERVER_CID" /run/secrets)"
	[ "$secrets_type" = bind ] ||
		die "server has no /run/secrets bind mount; set GITHUB_APP_KEY_FILE to the key's host path"
	GITHUB_APP_KEY_FILE="$(find "$secrets_dir" -maxdepth 1 -type f -name '*.pem' -size +0 | head -n 1)"
fi
if [ -z "$GITHUB_APP_KEY_FILE" ] || [ ! -s "$GITHUB_APP_KEY_FILE" ]; then
	die "GitHub App private key not found"
fi
log "ok: .env and GitHub App key present"

check_signin_settings "$SERVER_CID" "https://$PUBLIC_HOST" || exit 1

pg_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$PG_CID")"
case "$pg_health" in
healthy) ;;
none) docker exec "$PG_CID" pg_isready -q || die "Postgres is not accepting connections" ;;
*) die "Postgres health is '$pg_health'" ;;
esac
log "ok: Postgres is healthy"

applied="$(psql_ro "SELECT string_agg(version, ' ' ORDER BY version) FROM schema_migrations")" ||
	die "could not read schema_migrations"
EXPECTED_MIGRATION="$(cd "$DEPLOY_DIR/backend/migrations" && find . -maxdepth 1 -name '*.up.sql' | sed 's#^\./##' | sort | tail -n 1)"
log "ok: applied migrations: $applied"
log "    this commit's latest migration: $EXPECTED_MIGRATION"

db_bytes="$(psql_ro "SELECT pg_database_size(current_database())")"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
need_backup_gb=$(((db_bytes * 2) / 1073741824 + 1))
[ "$(free_gb "$BACKUP_DIR")" -ge "$need_backup_gb" ] ||
	die "less than ${need_backup_gb}G free for the database backup in $BACKUP_DIR"
[ "$(free_gb "$docker_root")" -ge "$MIN_FREE_GB" ] ||
	die "less than ${MIN_FREE_GB}G free in $docker_root for image builds"
log "ok: disk space (database is $((db_bytes / 1048576))M)"

# Nginx must serve exactly the directory this script updates.
[ "$(docker inspect --format '{{.State.Status}}' "$NGINX_CONTAINER" 2>/dev/null)" = running ] ||
	die "$NGINX_CONTAINER is not running"
read -r web_type web_src <<<"$(mount_source "$NGINX_CONTAINER" "$NGINX_WEB_ROOT")"
if [ "$web_type" != bind ] || [ ! -d "$FRONTEND_DIST" ] ||
	[ "$(realpath "$web_src")" != "$(realpath "$FRONTEND_DIST")" ]; then
	die "$NGINX_CONTAINER does not serve $FRONTEND_DIST at $NGINX_WEB_ROOT"
fi
# Same path is not enough: the bind mount must still hold this very directory.
dist_mount_matches ||
	die "$NGINX_CONTAINER's bind mount may reference a replaced copy of $FRONTEND_DIST, so a publish would not reach it. Reattach the mount before deploying (deploy/README.md, \"Frontend bind mount\"); this script does not restart Nginx. Nothing was changed."
DIST_OWNER="$(stat -c %U "$FRONTEND_DIST")"
# The script's umask 077 is right for backups and logs, but the frontend is
# public and the Nginx worker is neither its owner nor in its group. Files the
# owner writes here get the build's own modes (755/644) instead of 700/600.
as_dist_owner() { (umask 022 && runuser -u "$DIST_OWNER" -- "$@"); }
# make_dist_readable gives Nginx's worker what serving the frontend needs:
# search on the web root and on directories under assets/, and read on the
# assets and on the public files at the top of the web root -- index.html,
# and any robots.txt or favicon kept there, which a rollback restores with
# their recorded modes. It only adds bits and does not recurse outside
# assets/: hidden entries (.well-known/ above all) and other subdirectories
# keep whatever modes they have.
make_dist_readable() {
	as_dist_owner chmod go+rx "$FRONTEND_DIST" || return 1
	as_dist_owner find "$FRONTEND_DIST" -mindepth 1 -maxdepth 1 -type f ! -name '.*' -exec chmod go+r {} + || return 1
	[ ! -d "$FRONTEND_DIST/assets" ] ||
		as_dist_owner find "$FRONTEND_DIST/assets" \( -type d -exec chmod go+rx {} + \) -o \( -type f -exec chmod go+r {} + \)
}
log "ok: $NGINX_CONTAINER serves $FRONTEND_DIST (same directory and index.html inodes inside the container)"

# The smoke tests reach Nginx on its published HTTPS port, on this host.
https_binding="$(docker port "$NGINX_CONTAINER" 443/tcp 2>/dev/null | grep -E '^[0-9.]+:[0-9]+$' | head -n 1 || true)"
[ -n "$https_binding" ] || die "$NGINX_CONTAINER publishes no IPv4 host port for 443/tcp"
NGINX_HTTPS_PORT="${https_binding##*:}"
NGINX_HTTPS_IP="${https_binding%:*}"
[ "$NGINX_HTTPS_IP" != 0.0.0.0 ] || NGINX_HTTPS_IP=127.0.0.1

# A reload may be needed after the server is recreated (see the header), so the
# configuration on disk must be valid, and must be what Nginx already runs:
# no *.conf file may be newer than the oldest worker, which Nginx started when
# it last loaded its configuration. Otherwise a reload would also apply edits
# nobody has reviewed for this deployment.
if ! nginx_test="$(docker exec "$NGINX_CONTAINER" nginx -t 2>&1)"; then
	printf '%s\n' "$nginx_test" | redact
	die "nginx -t fails in $NGINX_CONTAINER; fix the configuration before deploying"
fi
worker_age="$(docker top "$NGINX_CONTAINER" -eo pid,etimes,args 2>/dev/null |
	awk '/nginx: worker process/ { if ($2 > max) max = $2 } END { print max + 0 }')"
[ "$worker_age" -gt 0 ] || die "cannot tell when $NGINX_CONTAINER last loaded its configuration (docker top found no workers)"
config_loaded_at=$(($(date +%s) - worker_age))
newest_config="$(docker exec "$NGINX_CONTAINER" sh -c \
	'find /etc/nginx -type f -name "*.conf" -exec stat -c %Y {} \; | sort -n | tail -n 1')"
[ -n "$newest_config" ] || die "cannot read the modification times of $NGINX_CONTAINER's configuration"
[ "$newest_config" -le $((config_loaded_at + 2)) ] ||
	die "a *.conf file under /etc/nginx in $NGINX_CONTAINER changed after Nginx last loaded its configuration; review and apply (or revert) that change yourself, then re-run preflight"
log "ok: Nginx configuration is valid and unchanged since Nginx loaded it"

# The live site must already work through Nginx: the API is proxied to the
# server, and / is this directory's index.html. How the API must answer is
# read from the image the server runs, which is also the image a rollback
# restores (see image_api_expectation).
PREVIOUS_API="$(image_api_expectation "$SERVER_OLD_ID")" || die "cannot tell whether the running server image requires sign-in"
API_EXPECT="$PREVIOUS_API"
log "running server image's /api/repos must answer: $API_EXPECT"
smoke_nginx "$(sha256sum "$FRONTEND_DIST/index.html" | cut -d' ' -f1)" ||
	die "https://$PUBLIC_HOST/ through $NGINX_CONTAINER ($NGINX_HTTPS_IP:$NGINX_HTTPS_PORT) does not serve /api/repos and $FRONTEND_DIST/index.html: $SMOKE_PROBLEM"
log "ok: the site answers through Nginx (/api/repos: $SMOKE_API_SEEN, and index.html)"

# The server must answer directly at HEALTH_URL, which the deployment uses to
# decide whether the new server is healthy. If it cannot be reached now, a
# deployment would recreate the server, apply migrations, and then roll back.
if ! current_health="$(curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null)" ||
	[[ "$current_health" != *'"status":"ok"'* ]]; then
	log "the server's published ports: $(docker port "$SERVER_CID" 2>/dev/null | tr '\n' ' ')"
	die "the current server does not report healthy at $HEALTH_URL; fix that (or set HEALTH_URL) before deploying"
fi
log "ok: current server reports healthy at $HEALTH_URL"

# The live server must be connected to the Postgres this script backs up and
# checks. Otherwise the backup protects the wrong database and the migration
# lands somewhere unverified. The requests above have just made the server use
# a pooled connection, so it shows up here by its container IP.
ip_list=""
for ip in $(container_ips "$SERVER_CID"); do
	[[ "$ip" =~ ^[0-9.]+$ ]] && ip_list="${ip_list:+$ip_list,}'$ip'"
done
[ -n "$ip_list" ] || die "could not determine the server container's IP address"
connected="$(psql_ro "SELECT count(*) FROM pg_stat_activity WHERE host(client_addr) IN ($ip_list)")" ||
	die "could not read pg_stat_activity"
[ "${connected:-0}" -gt 0 ] ||
	die "the running server has no connection to this Postgres; it may use a different database"
log "ok: the running server is connected to this Postgres"

# Nginx reached the server above, so it currently resolves these addresses.
NGINX_UPSTREAM_IPS="$(container_ips "$SERVER_CID")"

log "preflight passed"
if [ "$MODE" = preflight ]; then
	log "plan: build ${SHA:0:12} into $SERVER_REF and $WORKER_REF, back up the database to $BACKUP_DIR,"
	log "      recreate '$SERVER_SERVICE', then $([ "$WORKER_PRESENT" -eq 1 ] && echo "recreate and start '$WORKER_SERVICE' (now $WORKER_STATE)" || echo "create '$WORKER_SERVICE'") with project '$PROJECT',"
	log "      publish the frontend to $FRONTEND_DIST;"
	log "      Nginx is reloaded only if the server's address ($NGINX_UPSTREAM_IPS) changes"
	log "preflight only: no changes were made"
	result preflight-ok
	exit 0
fi

[ "$CI_OVERRIDE" -eq 0 ] || log "WARNING: deploying with the emergency CI override; CI did not pass for ${SHA:0:12}"

# Deploy mode keeps its log and backups here. An existing directory is used as
# it is; only a newly created one gets its mode set.
[ -d "$BACKUP_DIR" ] || install -d -m 700 "$BACKUP_DIR"
[ -d "$BACKUP_DIR/logs" ] || install -d -m 700 "$BACKUP_DIR/logs"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BUILD_LOG="$BACKUP_DIR/logs/deploy-$TS-${SHA:0:12}.log"
: >"$BUILD_LOG"

# ------------------------------------------------------------------ build --
# Nothing live changes in this phase.

log "building server and worker images (log: $BUILD_LOG)"
NEW_TAG="sbomdelta-deploy-${SHA:0:12}"
bounded docker build --target server -t "$SERVER_REPO:$NEW_TAG" "$DEPLOY_DIR/backend" >>"$BUILD_LOG" 2>&1 ||
	die "server image build failed"
bounded docker build --target worker -t "$WORKER_REPO:$NEW_TAG" "$DEPLOY_DIR/backend" >>"$BUILD_LOG" 2>&1 ||
	die "worker image build failed"
SERVER_NEW_ID="$(docker image inspect --format '{{.Id}}' "$SERVER_REPO:$NEW_TAG")"
WORKER_NEW_ID="$(docker image inspect --format '{{.Id}}' "$WORKER_REPO:$NEW_TAG")"
# This release has dashboard sign-in, so its image must say so; an unlabelled
# build would be checked against the wrong expectation after the switch.
NEW_API="$(image_api_expectation "$SERVER_NEW_ID")" || die "cannot read the new server image's sign-in label"
[ "$NEW_API" = signin ] || die "the new server image does not declare $SIGNIN_LABEL=required"
log "ok: images built (the new server image requires sign-in)"

log "building the frontend in $NODE_IMAGE"
bounded docker run --rm --user "$BUILD_UID:$BUILD_GID" \
	-e HOME=/tmp -e npm_config_cache=/tmp/.npm -e npm_config_update_notifier=false \
	-v "$DEPLOY_DIR/frontend:/app" -w /app "$NODE_IMAGE" \
	sh -c 'npm ci --no-audit --no-fund && npm run build' >>"$BUILD_LOG" 2>&1 ||
	die "frontend build failed"
NEW_DIST="$DEPLOY_DIR/frontend/dist"
[ -s "$NEW_DIST/index.html" ] || die "frontend build produced no index.html"
mapfile -t assets < <(grep -oE '(src|href)="/?assets/[^"]+"' "$NEW_DIST/index.html" | sed -E 's#^[a-z]+="/?##; s#"$##')
[ "${#assets[@]}" -gt 0 ] || die "frontend index.html references no assets"
for asset in "${assets[@]}"; do
	[ -s "$NEW_DIST/$asset" ] || die "frontend build is missing $asset"
done
log "ok: frontend built (${#assets[@]} entry assets)"

# ----------------------------------------------------------------- backup --

DB_BACKUP="$BACKUP_DIR/db-$PROJECT-$TS-${SHA:0:12}.dump"
log "backing up the database to $DB_BACKUP"
# shellcheck disable=SC2016 # expanded inside the container, on purpose
bounded docker exec "$PG_CID" sh -c 'u="${POSTGRES_USER:-postgres}"; exec pg_dump -U "$u" -d "${POSTGRES_DB:-$u}" -Fc' \
	>"$DB_BACKUP.partial" 2>>"$BUILD_LOG" || die "database backup failed"
mv "$DB_BACKUP.partial" "$DB_BACKUP"
chmod 600 "$DB_BACKUP"
[ -s "$DB_BACKUP" ] || die "database backup is empty"
docker exec -i "$PG_CID" pg_restore --list <"$DB_BACKUP" >/dev/null 2>>"$BUILD_LOG" ||
	die "database backup is not a readable archive"
log "ok: database backup verified ($(($(stat -c %s "$DB_BACKUP") / 1024))K)"

FRONTEND_BACKUP="$BACKUP_DIR/frontend-dist-$TS.tar.gz"
tar -C "$FRONTEND_DIST" -czf "$FRONTEND_BACKUP" .
log "ok: current frontend saved to $FRONTEND_BACKUP"

# Retention applies only to files this script names.
find "$BACKUP_DIR" -maxdepth 1 -name 'db-*.dump' -printf '%T@ %p\n' | sort -rn |
	tail -n +"$((KEEP_BACKUPS + 1))" | cut -d' ' -f2- | xargs -r rm -f --
find "$BACKUP_DIR" -maxdepth 1 -name 'frontend-dist-*.tar.gz' -printf '%T@ %p\n' | sort -rn |
	tail -n +"$((KEEP_BACKUPS + 1))" | cut -d' ' -f2- | xargs -r rm -f --

# ------------------------------------------------------------- switchover --

require_time "$SWITCHOVER_RESERVE" "the switchover"

docker tag "$SERVER_OLD_ID" "$SERVER_REPO:sbomdelta-rollback"
[ "$WORKER_PRESENT" -eq 0 ] || docker tag "$WORKER_OLD_ID" "$WORKER_REPO:sbomdelta-rollback"

log "recreating '$SERVER_SERVICE' (applies migrations on start)"
SERVER_SWITCHED=1
docker tag "$SERVER_REPO:$NEW_TAG" "$SERVER_REF"
compose up -d --no-deps --no-build "$SERVER_SERVICE" >>"$BUILD_LOG" 2>&1 || die "could not recreate the server"
wait_for_container "$SERVER_SERVICE" "$SERVER_NEW_ID" || die "server container is not running the new image"
wait_for_health || die "server did not report healthy within ${HEALTH_TIMEOUT}s"
log "ok: server healthy"

# The server and this check must see the same database, or the backup above
# protected the wrong one.
[ "$(psql_ro "SELECT count(*) FROM schema_migrations WHERE version = '$EXPECTED_MIGRATION'")" = 1 ] ||
	die "$EXPECTED_MIGRATION is not recorded in the database the server should be using"
log "ok: migration $EXPECTED_MIGRATION applied"

refresh_nginx_upstream || die "could not point Nginx at the new server"
# From here on every check is of the new server image.
API_EXPECT="$NEW_API"
wait_for_nginx || die "the new server does not answer through Nginx"
log "ok: the new server answers through Nginx"

if [ "$WORKER_PRESENT" -eq 1 ]; then log "recreating '$WORKER_SERVICE'"; else log "creating '$WORKER_SERVICE'"; fi
WORKER_SWITCHED=1
docker tag "$WORKER_REPO:$NEW_TAG" "$WORKER_REF"
compose up -d --no-deps --no-build "$WORKER_SERVICE" >>"$BUILD_LOG" 2>&1 || die "could not create or recreate the worker"
wait_for_container "$WORKER_SERVICE" "$WORKER_NEW_ID" || die "worker is not running steadily on the new image"
log "ok: worker running"

# ---------------------------------------------------------------- frontend --
# The directory itself is bind-mounted into Nginx, so it is updated in place,
# never replaced. New files land first and index.html last, so a visitor never
# gets an index pointing at assets that do not exist yet. Only stale files
# under assets/ are pruned; everything else in the directory, including any
# .well-known/ certbot webroot, is left alone.

log "publishing the frontend to $FRONTEND_DIST"
FRONTEND_TOUCHED=1
tar -C "$NEW_DIST" --exclude=./index.html -cf - . | as_dist_owner tar -C "$FRONTEND_DIST" -xf - ||
	die "could not copy frontend assets"
# Before the new index.html goes live, so it never points at assets Nginx
# cannot read. Also repairs a directory left too narrow by an earlier run.
make_dist_readable || die "could not make the frontend readable by Nginx"
as_dist_owner cp "$NEW_DIST/index.html" "$FRONTEND_DIST/.index.html.new"
as_dist_owner mv -f "$FRONTEND_DIST/.index.html.new" "$FRONTEND_DIST/index.html"
if [ -d "$FRONTEND_DIST/assets" ] && [ -d "$NEW_DIST/assets" ]; then
	comm -23 \
		<(cd "$FRONTEND_DIST/assets" && find . -type f | sort) \
		<(cd "$NEW_DIST/assets" && find . -type f | sort) |
		while IFS= read -r stale; do as_dist_owner rm -f -- "$FRONTEND_DIST/assets/$stale"; done
fi

cmp -s "$NEW_DIST/index.html" "$FRONTEND_DIST/index.html" || die "published index.html does not match the build"
for asset in "${assets[@]}"; do
	[ -s "$FRONTEND_DIST/$asset" ] || die "published frontend is missing $asset"
done
INDEX_SHA="$(sha256sum "$FRONTEND_DIST/index.html" | cut -d' ' -f1)"
[ "$(docker exec "$NGINX_CONTAINER" sha256sum "$NGINX_WEB_ROOT/index.html" | cut -d' ' -f1)" = "$INDEX_SHA" ] ||
	die "$NGINX_CONTAINER does not see the published index.html"

# The final smoke test, through Nginx: the API answers and / is the new build.
wait_for_nginx "$INDEX_SHA" || die "the site does not serve the new release through Nginx"
log "ok: frontend published; the site serves the new release through Nginx"

# ------------------------------------------------------------------ record --

printf '%s\n' "$SHA" >"$BACKUP_DIR/current-sha"
printf '%s %s project=%s db_backup=%s ci_override=%s\n' "$TS" "$SHA" "$PROJECT" "$DB_BACKUP" "$CI_OVERRIDE" >>"$BACKUP_DIR/deploy-history.log"
# Drop the temporary build tags. The images stay, tagged as the service refs.
docker rmi "$SERVER_REPO:$NEW_TAG" "$WORKER_REPO:$NEW_TAG" >/dev/null 2>&1 || true

log "deployed ${SHA:0:12} successfully"
# api= is how the running server image answers an anonymous /api/repos, for
# the CD workflow's check from outside (deploy/ssm-result.sh).
result deployed "index_sha256=$INDEX_SHA api=$NEW_API"
