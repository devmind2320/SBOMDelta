#!/usr/bin/env bash
# The sh -c snippets below take their values as arguments, on purpose.
# shellcheck disable=SC2016
#
# run-tests.sh -- regression tests for the deployment scripts that can run
# without production: the bootstrap's lock and checkout handling (against
# throwaway git repositories), the result-marker parser, output redaction, and
# the destructive-command guard. deploy.sh itself needs Docker and root, and is
# covered by ShellCheck and its own preflight.
#
# Runs on Linux (CI) and macOS. Usage: deploy/tests/run-tests.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -r -f -- "$WORK"' EXIT

failures=0
pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }
check() { # check <name> <command...>
	local name="$1"
	shift
	if "$@"; then pass "$name"; else fail "$name"; fi
}
contains() { grep -qF -- "$2" <<<"$1"; }
# exit_code_is <output> <N>: the output reports exactly "rc=N", so a failure
# such as rc=127 (command not found) cannot pass for rc=1.
exit_code_is() { grep -qE "(^|[[:space:]])rc=$2([[:space:]]|\$)" <<<"$1"; }

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

# macOS has no flock(1). This stand-in locks an inherited descriptor exactly as
# flock(1) does: the lock belongs to the open file description, so it outlives
# this short-lived process for as long as the caller keeps the descriptor.
if ! command -v flock >/dev/null; then
	mkdir "$WORK/bin"
	cat >"$WORK/bin/flock" <<'EOF'
#!/usr/bin/env python3
import fcntl, sys
args = sys.argv[1:]
flags = fcntl.LOCK_EX
while args and args[0].startswith("-"):
    if args[0] == "-n":
        flags |= fcntl.LOCK_NB
    args = args[1:]
try:
    fcntl.flock(int(args[0]), flags)
except BlockingIOError:
    sys.exit(1)
EOF
	chmod +x "$WORK/bin/flock"
	export PATH="$WORK/bin:$PATH"
fi

# ------------------------------------------------------------- bootstrap --

# A stub deploy.sh, committed in the throwaway repository, reports what the
# bootstrap handed it and can pause until the test lets it finish.
cat >"$WORK/stub-deploy.sh" <<'EOF'
#!/usr/bin/env bash
echo "stub args: $*"
echo "stub script: ${BASH_SOURCE[0]}"
echo "stub DEPLOY_DIR=$DEPLOY_DIR"
if ( exec 8>>"$DEPLOY_LOCK_FILE"; flock -n 8 ); then echo "stub lock: free"; else echo "stub lock: held"; fi
if [ -n "${STUB_HOLD:-}" ]; then
	touch "$STUB_HOLD.started"
	while [ ! -e "$STUB_HOLD.release" ]; do sleep 0.1; done
fi
echo "stub HEAD at end: $(git -C "$DEPLOY_DIR" rev-parse HEAD)"
EOF

git init -q --bare "$WORK/origin.git"
git -C "$WORK/origin.git" symbolic-ref HEAD refs/heads/main
git clone -q "$WORK/origin.git" "$WORK/seed" 2>/dev/null
git -C "$WORK/seed" checkout -q -b main
mkdir -p "$WORK/seed/deploy"
cp "$WORK/stub-deploy.sh" "$WORK/seed/deploy/deploy.sh"
git -C "$WORK/seed" add deploy/deploy.sh
git -C "$WORK/seed" commit -q -m one
SHA1="$(git -C "$WORK/seed" rev-parse HEAD)"
echo two >"$WORK/seed/file"
git -C "$WORK/seed" add file
git -C "$WORK/seed" commit -q -m two
SHA2="$(git -C "$WORK/seed" rev-parse HEAD)"
git -C "$WORK/seed" push -q origin main
git -C "$WORK/seed" checkout -q -b side
echo side >"$WORK/seed/file"
git -C "$WORK/seed" commit -q -am side
SIDE="$(git -C "$WORK/seed" rev-parse HEAD)"
git -C "$WORK/seed" push -q origin side
git clone -q "$WORK/origin.git" "$WORK/checkout"
git -C "$WORK/checkout" checkout -q --detach "$SHA1"
mkdir "$WORK/scratch"

# bootstrap <sha> [mode] runs the bootstrap as SSM would: plain assignments,
# then the file's text, through sh.
bootstrap() {
	{
		printf "DEPLOY_DIR='%s'\nSHA=%s\nMODE=%s\nSKIP_OLDER=%s\nCI_OVERRIDE=%s\n" \
			"$WORK/checkout" "$1" "${2:-deploy}" "${SKIP_OLDER:-0}" "${CI_OVERRIDE:-0}"
		cat "$ROOT/deploy/bootstrap.sh"
	} >"$WORK/command.sh"
	LOCK_FILE="$WORK/deploy.lock" SCRATCH_DIR="$WORK/scratch" sh "$WORK/command.sh"
}
head_of() { git -C "$WORK/checkout" rev-parse HEAD; }

out="$(bootstrap "$SHA2" 2>&1)" && rc=0 || rc=$?
check "bootstrap: runs deploy.sh for a commit on main" [ "$rc" -eq 0 ]
check "bootstrap: checks out exactly the commit" [ "$(head_of)" = "$SHA2" ]
check "bootstrap: passes --deploy-dir and the mode" contains "$out" "stub args: --sha $SHA2 --mode deploy --deploy-dir $WORK/checkout"
check "bootstrap: exports DEPLOY_DIR to deploy.sh" contains "$out" "stub DEPLOY_DIR=$WORK/checkout"
check "bootstrap: deploy.sh still holds the lock" contains "$out" "stub lock: held"
script_line="$(grep '^stub script: ' <<<"$out" || true)"
check "bootstrap: runs a private copy, not the checkout's file" \
	contains "$script_line" "stub script: $WORK/scratch/sbomdelta-deploy."
check "bootstrap: the private copy is not left in the checkout" \
	[ -z "$(git -C "$WORK/checkout" status --porcelain)" ]

out="$(SKIP_OLDER=1 CI_OVERRIDE=1 bootstrap "$SHA2" preflight 2>&1)" || true
check "bootstrap: passes --skip-if-older and --ci-override" \
	contains "$out" "--mode preflight --deploy-dir $WORK/checkout --skip-if-older --ci-override"

# The concurrency regression: while one deployment runs, a second one (say,
# the next workflow run after the first was cancelled) must not fetch or check
# out anything, and the first must keep its commit to the end.
git -C "$WORK/checkout" checkout -q --detach "$SHA2"
rm -f "$WORK/hold.started" "$WORK/hold.release"
STUB_HOLD="$WORK/hold" bootstrap "$SHA2" >"$WORK/first.out" 2>&1 &
first=$!
for _ in $(seq 1 100); do [ -e "$WORK/hold.started" ] && break; sleep 0.1; done
check "lock: the first deployment is running" [ -e "$WORK/hold.started" ]
rm -f "$WORK/checkout/.git/FETCH_HEAD"
out="$(bootstrap "$SHA1" 2>&1)" && rc=0 || rc=$?
check "lock: a second deployment is refused (exit 75)" [ "$rc" -eq 75 ]
check "lock: the refusal says nothing changed" contains "$out" "nothing was changed"
check "lock: the second deployment did not check anything out" [ "$(head_of)" = "$SHA2" ]
check "lock: the second deployment did not fetch" [ ! -e "$WORK/checkout/.git/FETCH_HEAD" ]
touch "$WORK/hold.release"
wait "$first" && rc=0 || rc=$?
check "lock: the first deployment finishes normally" [ "$rc" -eq 0 ]
check "lock: the first deployment kept its commit throughout" contains "$(cat "$WORK/first.out")" "stub HEAD at end: $SHA2"
out="$(bootstrap "$SHA1" 2>&1)" && rc=0 || rc=$?
check "lock: released once the first deployment exits" [ "$rc" -eq 0 ]

out="$(bootstrap "$SIDE" 2>&1)" && rc=0 || rc=$?
check "bootstrap: refuses a commit that is not on main" [ "$rc" -ne 0 ]
check "bootstrap: says why" contains "$out" "is not on origin/main"
check "bootstrap: leaves the checkout alone when refusing" [ "$(head_of)" = "$SHA1" ]

echo dirty >>"$WORK/checkout/deploy/deploy.sh"
rm -f "$WORK/checkout/.git/FETCH_HEAD"
out="$(bootstrap "$SHA2" 2>&1)" && rc=0 || rc=$?
check "bootstrap: refuses a checkout with local changes" [ "$rc" -ne 0 ]
check "bootstrap: does not fetch into a modified checkout" [ ! -e "$WORK/checkout/.git/FETCH_HEAD" ]
git -C "$WORK/checkout" checkout -q -- deploy/deploy.sh

# (The workflow validates these before rendering the command; the bootstrap
# checks again.)
for bad in "abc" "$(tr a-f A-F <<<"$SHA1")" "${SHA1}0"; do
	out="$(bootstrap "$bad" 2>&1)" && rc=0 || rc=$?
	check "bootstrap: rejects SHA '${bad:0:12}...' before locking" [ "$rc" -ne 0 ] && contains "$out" "full lowercase commit id"
done
out="$(bootstrap "$SHA2" destroy 2>&1)" && rc=0 || rc=$?
check "bootstrap: rejects an unknown mode" [ "$rc" -ne 0 ]
check "bootstrap: the rejections left the checkout alone" [ "$(head_of)" = "$SHA1" ]

# ---------------------------------------------------------- result marker --

S="$(printf 'a%.0s' {1..40})"
H="$(printf 'b%.0s' {1..64})"
parse() { "$ROOT/deploy/ssm-result.sh" "$@" 2>/dev/null; }

out="$(printf '[t] log\nSBOMDELTA_RESULT status=deployed sha=%s index_sha256=%s\n' "$S" "$H" | parse deploy "$S" 0)" && rc=0 || rc=$?
check "marker: deployed run yields its index checksum" [ "$rc:$out" = "0:result=deployed"$'\n'"index_sha=$H" ]
out="$(printf 'SBOMDELTA_RESULT status=skipped-older sha=%s deployed=%s\n' "$S" "$S" | parse deploy "$S" 1)" && rc=0 || rc=$?
check "marker: skipped-older is accepted for an automatic run" [ "$rc:$out" = "0:result=skipped-older"$'\n'"index_sha=" ]
check "marker: skipped-older is refused when skipping was not allowed" \
	sh -c '! printf "SBOMDELTA_RESULT status=skipped-older sha=%s deployed=x\n" "$1" | "$2" deploy "$1" 0 2>/dev/null' _ "$S" "$ROOT/deploy/ssm-result.sh"
check "marker: preflight-ok fits a preflight" sh -c 'printf "SBOMDELTA_RESULT status=preflight-ok sha=%s\n" "$1" | "$2" preflight "$1" 0 >/dev/null 2>&1' _ "$S" "$ROOT/deploy/ssm-result.sh"
truncated="$(printf '[t] line %s\n' $(seq 1 50))"
check "marker: missing marker (truncated output) fails" sh -c '! printf "%s\n" "$1" | "$2" deploy "$3" 0 2>/dev/null' _ "$truncated" "$ROOT/deploy/ssm-result.sh" "$S"
check "marker: empty output fails" sh -c '! printf "" | "$1" deploy "$2" 0 2>/dev/null' _ "$ROOT/deploy/ssm-result.sh" "$S"
check "marker: a marker for another commit fails" \
	sh -c '! printf "SBOMDELTA_RESULT status=deployed sha=%s index_sha256=%s\n" "$(printf c%.0s $(seq 1 40))" "$1" | "$2" deploy "$3" 0 2>/dev/null' _ "$H" "$ROOT/deploy/ssm-result.sh" "$S"
check "marker: deployed without a checksum fails" \
	sh -c '! printf "SBOMDELTA_RESULT status=deployed sha=%s\n" "$1" | "$2" deploy "$1" 0 2>/dev/null' _ "$S" "$ROOT/deploy/ssm-result.sh"
check "marker: deployed with a malformed checksum fails" \
	sh -c '! printf "SBOMDELTA_RESULT status=deployed sha=%s index_sha256=xyz\n" "$1" | "$2" deploy "$1" 0 2>/dev/null' _ "$S" "$ROOT/deploy/ssm-result.sh"
check "marker: preflight result does not satisfy a deploy" \
	sh -c '! printf "SBOMDELTA_RESULT status=preflight-ok sha=%s\n" "$1" | "$2" deploy "$1" 0 2>/dev/null' _ "$S" "$ROOT/deploy/ssm-result.sh"
check "marker: two markers fail" \
	sh -c '! printf "SBOMDELTA_RESULT status=preflight-ok sha=%s\nSBOMDELTA_RESULT status=preflight-ok sha=%s\n" "$1" "$1" | "$2" preflight "$1" 0 2>/dev/null' _ "$S" "$ROOT/deploy/ssm-result.sh"
check "marker: only a marker at the start of a line counts" \
	sh -c '! printf "echo SBOMDELTA_RESULT status=preflight-ok sha=%s\n" "$1" | "$2" preflight "$1" 0 2>/dev/null' _ "$S" "$ROOT/deploy/ssm-result.sh"

# ------------------------------------------------------------- redaction --

embedded="$(awk '/^REDACT_SED$/ { on = 0 } on { print } /<<.REDACT_SED./ { on = 1 }' "$ROOT/deploy/deploy.sh")"
check "redact: deploy.sh embeds deploy/redact.sed verbatim" [ "$embedded" = "$(cat "$ROOT/deploy/redact.sed")" ]
sample="$(printf 'DATABASE_URL=postgres://u:pw@h/db\nAuthorization: Bearer abcdefgh\nplain line\n')"
check "redact: the embedded program, passed as one argument, behaves the same" \
	[ "$(printf '%s\n' "$sample" | sed -E "$embedded")" = "$(printf '%s\n' "$sample" | sed -E -f "$ROOT/deploy/redact.sed")" ]

redact() { sed -E -f "$ROOT/deploy/redact.sed"; }
# Each case: input, then a fragment that must not survive.
while IFS='|' read -r input secret; do
	[ -n "$input" ] || continue
	out="$(printf '%s\n' "$input" | redact)"
	check "redact: ${input:0:40}" sh -c '! printf "%s" "$1" | grep -qF -- "$2"' _ "$out" "$secret"
done <<'EOF'
DATABASE_URL=postgres://sbomdelta:hunter2pass@postgres:5432/db|hunter2pass
password=hunter2pass|hunter2pass
DB_PASSWORD: "hunter2pass"|hunter2pass
GITHUB_WEBHOOK_SECRET=abcdef123456|abcdef123456
"client_secret": "abcdef123456"|abcdef123456
api_key=AbCdEf123456|AbCdEf123456
X-Api-Key: AbCdEf123456|AbCdEf123456
aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY|wJalrXUtnFEMI
Authorization: Bearer abc.def.ghi-jkl|abc.def.ghi-jkl
authorization=token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|ghp_aaaa
curl -H "Bearer s3cr3tT0ken123"|s3cr3tT0ken123
pushed with ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ok|ghp_aaaa
github_pat_11AAAAAAA0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbb|github_pat_11AAAAAAA0
key id AKIAIOSFODNN7EXAMPLE used|AKIAIOSFODNN7EXAMPLE
jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U|dozjgNryP4J3jVmNHl0w5N
anthropic sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa|sk-ant-api03-aaaa
google AIzaSyA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|AIzaSyA-aaaa
slack xoxb-123456789012-abcdefghij|xoxb-123456789012
stripe sk_live_aaaaaaaaaaaaaaaaaaaa|sk_live_aaaa
"key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"|MIIEowIBAAKCAQEA
EOF

pem="$(printf 'before\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\nafter\n' | redact)"
check "redact: multi-line PEM key body is masked" sh -c '! printf "%s" "$1" | grep -q MIIEvQIBADAN' _ "$pem"
check "redact: lines around a PEM key survive" sh -c 'printf "%s" "$1" | grep -q before && printf "%s" "$1" | grep -q after' _ "$pem"
cut_pem="$(printf -- '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBBBBBBBBBBBBBBBBBBBBBBB\n' | redact)"
check "redact: a PEM key cut off before its END line is masked" sh -c '! printf "%s" "$1" | grep -q MHcCAQEE' _ "$cut_pem"
plain="[01:02:03Z] ok: Compose project 'sbomdelta' (from container labels)"
check "redact: ordinary log lines are unchanged" [ "$(printf '%s\n' "$plain" | redact)" = "$plain" ]
marker="SBOMDELTA_RESULT status=deployed sha=$S index_sha256=$H"
check "redact: the result marker is unchanged" [ "$(printf '%s\n' "$marker" | redact)" = "$marker" ]

# ------------------------------------------------------- frontend restore --

# deploy.sh saves the frontend as root, mode 600, and restores it as the
# frontend directory's owner. The owner cannot open that file, so root must
# open it and stream it to tar. The permission test runs deploy.sh's own
# restore command, and only once it is exactly the expected one.
expected_restore='as_dist_owner tar -C "$FRONTEND_DIST" -xzf - <"$FRONTEND_BACKUP"'
restore_cmd="$(grep -m 1 'as_dist_owner tar -C "$FRONTEND_DIST" -xzf' "$ROOT/deploy/deploy.sh" |
	sed -E 's/^[[:space:]]*if //; s/; then$//' || true)"
if [ -z "$restore_cmd" ]; then
	fail "restore: deploy.sh has no frontend restore line (as_dist_owner tar -C \"\$FRONTEND_DIST\" -xzf ...)"
else
	check "restore: deploy.sh streams the backup to tar on stdin" [ "$restore_cmd" = "$expected_restore" ]
fi

# In CI the permission test must run; only a local run may skip it.
in_ci=0
if [ "${GITHUB_ACTIONS:-}" = true ] || [ "${CI:-}" = true ]; then in_ci=1; fi
missing=""
if [ "$(id -u)" -eq 0 ]; then
	as_root=(env)
elif sudo -n true 2>/dev/null; then
	as_root=(sudo -n env)
else
	as_root=()
	missing="$missing root-or-passwordless-sudo"
fi
if [ "${#as_root[@]}" -gt 0 ]; then
	# runuser lives in /usr/sbin, so look for it as root would.
	"${as_root[@]}" sh -c 'command -v runuser' >/dev/null 2>&1 || missing="$missing runuser"
elif ! command -v runuser >/dev/null; then
	missing="$missing runuser"
fi
id nobody >/dev/null 2>&1 || missing="$missing nobody-user"

# restore_scenario <backup dir mode>: root saves the frontend under umask 077
# into a backup directory with that mode; the owner, nobody, must be refused
# the file by path and get it back through deploy.sh's command.
restore_scenario() {
	local mode="$1" out
	out="$("${as_root[@]}" RESTORE_CMD="$restore_cmd" BACKUP_DIR_MODE="$mode" bash -c '
		set -u
		umask 077
		top="$(mktemp -d)"
		chmod 755 "$top"
		mkdir "$top/backups" "$top/dist"
		chmod "$BACKUP_DIR_MODE" "$top/backups"
		echo old >"$top/dist/index.html"
		FRONTEND_BACKUP="$top/backups/frontend-dist.tar.gz"
		tar -C "$top/dist" -czf "$FRONTEND_BACKUP" .
		echo new >"$top/dist/index.html"
		chmod 755 "$top/dist"
		chown -R nobody "$top/dist"
		FRONTEND_DIST="$top/dist"
		as_dist_owner() { runuser -u nobody -- "$@"; }
		echo "backup: $(stat -c "%U %a" "$FRONTEND_BACKUP"), dir: $(stat -c "%U %a" "$top/backups")"
		if as_dist_owner tar -C "$FRONTEND_DIST" -xzf "$FRONTEND_BACKUP" 2>/dev/null; then
			echo "by-path: opened"
		else
			echo "by-path: refused"
		fi
		if eval "$RESTORE_CMD"; then echo "restore: ok $(cat "$FRONTEND_DIST/index.html")"; fi
		chmod -R u+w "$top"; rm -r -f -- "$top"
	' 2>&1)"
	check "restore ($mode dir): the backup is root-owned, mode 600, in a mode-$mode directory" \
		contains "$out" "backup: root 600, dir: root $mode"
	check "restore ($mode dir): the owner cannot open the backup by path (the old bug)" contains "$out" "by-path: refused"
	check "restore ($mode dir): deploy.sh's command restores it as the owner" contains "$out" "restore: ok old"
}

if [ -n "$missing" ]; then
	if [ "$in_ci" -eq 1 ]; then
		fail "restore: the permission test cannot run in CI; missing:$missing"
	else
		echo "skip restore: the permission test needs root or passwordless sudo, runuser and a 'nobody' user; missing:$missing (in CI this is a failure)"
	fi
elif [ "$restore_cmd" != "$expected_restore" ]; then
	fail "restore: permission test not run, because deploy.sh's restore line is not the expected command"
else
	# 700: a backup directory the deploy created. 755: a pre-existing one the
	# owner can enter, where the file's own mode 600 is what refuses it.
	restore_scenario 700
	restore_scenario 755
fi

# ------------------------------------------------------- container lookup --

# deploy.sh's own lookup functions, run against a stand-in `docker` that
# applies label filters to canned containers the way `docker ps -a` does.
# Rows: ID NAME STATE PROJECT SERVICE ONEOFF.
lookup_functions="$(awk '
	/^(service_containers|describe_containers|container_for|resolve_worker)\(\) \{$/ { on = 1 }
	on { print }
	on && /^\}$/ { on = 0 }
' "$ROOT/deploy/deploy.sh")"
check "lookup: deploy.sh defines the four container lookup functions" \
	[ "$(grep -cE '^(service_containers|describe_containers|container_for|resolve_worker)\(\) \{$' <<<"$lookup_functions")" -eq 4 ]

mkdir -p "$WORK/fakebin"
cat >"$WORK/fakebin/docker" <<'EOF'
#!/usr/bin/env bash
[ "${FAKE_DOCKER_FAIL:-0}" = 1 ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
# exec <container> stat -c %i <path>: the container's web root is whichever
# host directory FAKE_NGINX_DIR names, as a bind mount would make it.
if [ "$1" = exec ]; then
	[ "${FAKE_EXEC_FAIL:-0}" = 1 ] && { echo "OCI runtime exec failed" >&2; exit 126; }
	shift 2
	[ "$1 $2 $3" = "stat -c %i" ] || { echo "fake docker: unexpected exec $*" >&2; exit 2; }
	case "$4" in
	"$FAKE_WEB_ROOT") target="$FAKE_NGINX_DIR" ;;
	"$FAKE_WEB_ROOT/index.html") target="${FAKE_NGINX_INDEX:-$FAKE_NGINX_DIR/index.html}" ;;
	*) echo "fake docker: unexpected path $4" >&2; exit 2 ;;
	esac
	[ "${FAKE_EXEC_GARBAGE:-0}" = 1 ] && { echo "sh: stat: not found"; exit 0; }
	exec stat -c %i "$target"
fi
[ "$1" = ps ] || { echo "fake docker: unexpected command $*" >&2; exit 2; }
project="" service="" oneoff=""
while [ $# -gt 0 ]; do
	case "$1" in
	--filter)
		case "$2" in
		label=com.docker.compose.project=*) project="${2#label=com.docker.compose.project=}" ;;
		label=com.docker.compose.service=*) service="${2#label=com.docker.compose.service=}" ;;
		label=com.docker.compose.oneoff=*) oneoff="${2#label=com.docker.compose.oneoff=}" ;;
		esac
		shift 2 ;;
	*) shift ;;
	esac
done
while read -r id name state p s o; do
	[ -n "$id" ] || continue
	[ -z "$project" ] || [ "$p" = "$project" ] || continue
	[ -z "$service" ] || [ "$s" = "$service" ] || continue
	[ -z "$oneoff" ] || [ "$o" = "$oneoff" ] || continue
	echo "$id $name $state"
done <"$FAKE_DOCKER_ROWS"
EOF
chmod +x "$WORK/fakebin/docker"

# lookup <rows> <function> [args]: runs one lookup function in a subshell with
# the stand-in docker; prints its stdout, then the worker variables, then
# "rc=N" and its stderr.
lookup() {
	printf '%s\n' "$1" >"$WORK/rows"
	shift
	(
		# The stand-ins apply to this subshell only, on purpose.
		# shellcheck disable=SC2030
		PATH="$WORK/fakebin:$PATH"
		export FAKE_DOCKER_ROWS="$WORK/rows"
		# Read by the functions loaded with eval below.
		# shellcheck disable=SC2034
		PROJECT=sbomdelta WORKER_SERVICE=worker
		WORKER_PRESENT="" WORKER_CID="" WORKER_STATE=""
		# shellcheck disable=SC2317,SC2329
		log() { printf '%s\n' "$*"; }
		eval "$lookup_functions"
		if "$@" 2>"$WORK/lookup.err"; then rc=0; else rc=$?; fi
		echo "present=$WORKER_PRESENT cid=$WORKER_CID state=$WORKER_STATE rc=$rc"
		cat "$WORK/lookup.err"
	)
}

base='s1 sbomdelta-server-1 running sbomdelta server False
p1 sbomdelta-postgres-1 running sbomdelta postgres False
m1 sbomdelta-minio-1 running sbomdelta minio False
n1 sbomdelta-nginx running sbomdelta nginx False'

out="$(lookup "$base" resolve_worker)"
check "worker absent: accepted, not an error" contains "$out" "present=0 cid= state=absent rc=0"

out="$(lookup "$base"$'\n''w1 sbomdelta-worker-1 exited sbomdelta worker False' resolve_worker)"
check "worker stopped: found, with its state" contains "$out" "present=1 cid=w1 state=exited rc=0"

out="$(lookup "$base"$'\n''w1 sbomdelta-worker-1 running sbomdelta worker False' resolve_worker)"
check "worker running: found, with its state" contains "$out" "present=1 cid=w1 state=running rc=0"

out="$(lookup "$base"$'\n''w1 sbomdelta-worker-1 running sbomdelta worker False'$'\n''w2 abc123_sbomdelta-worker-1 exited sbomdelta worker False' resolve_worker)"
check "worker multiple: refused" exit_code_is "$out" 1
check "worker multiple: names every container and its state" \
	contains "$out" "found 2: sbomdelta-worker-1 (running), abc123_sbomdelta-worker-1 (exited)"

out="$(lookup "$base"$'\n''w1 sbomdelta-worker-1 running sbomdelta worker False'$'\n''r1 sbomdelta-worker-run-1a2b exited sbomdelta worker True' resolve_worker)"
check "worker: a one-off run container is ignored next to the real one" contains "$out" "present=1 cid=w1 state=running rc=0"
out="$(lookup "$base"$'\n''r1 sbomdelta-worker-run-1a2b exited sbomdelta worker True' resolve_worker)"
check "worker: a one-off run container alone counts as absent" contains "$out" "present=0 cid= state=absent rc=0"
out="$(lookup "$base"$'\n''x1 other-worker-1 running otherproject worker False' resolve_worker)"
check "worker: another project's worker is ignored" contains "$out" "present=0 cid= state=absent rc=0"

out="$(FAKE_DOCKER_FAIL=1 lookup "$base" resolve_worker)"
check "worker: a Docker failure is an error, not 'absent'" exit_code_is "$out" 1

out="$(lookup "$base" container_for server)"
check "strict: one server container is returned" contains "$out" $'s1\npresent= cid= state= rc=0'
for svc in postgres minio nginx; do
	out="$(lookup "$(grep -v " $svc False" <<<"$base")" container_for "$svc")"
	check "strict: a missing $svc container is refused" contains "$out" "expected exactly one container for service '$svc' in project 'sbomdelta', found 0"
done
out="$(lookup "$base"$'\n''s2 abc123_sbomdelta-server-1 exited sbomdelta server False' container_for server)"
check "strict: two server containers are refused and listed" \
	contains "$out" "found 2: sbomdelta-server-1 (running), abc123_sbomdelta-server-1 (exited)"
out="$(lookup "$base"$'\n''r2 sbomdelta-server-run-9f8e exited sbomdelta server True' container_for server)"
check "strict: a one-off server container is ignored" contains "$out" $'s1\npresent= cid= state= rc=0'

# ------------------------------------------------- frontend bind mount --

# Docker binds the directory that existed when Nginx started. If frontend/dist
# is replaced afterwards, the path still matches but Nginx serves the old
# directory, and a publish never reaches it (a failed deployment). Preflight
# must compare inodes, not paths. These run deploy.sh's dist_mount_matches
# against real directories, with the stand-in docker playing the container.
identity_function="$(awk '/^dist_mount_matches\(\) \{$/ { on = 1 } on { print } on && /^\}$/ { on = 0 }' "$ROOT/deploy/deploy.sh")"
check "bind mount: deploy.sh defines dist_mount_matches" grep -q '^dist_mount_matches() {$' <<<"$identity_function"
check "bind mount: preflight stops on a mismatch, asking for the mount to be reattached" \
	grep -qE '^dist_mount_matches \|\|$' "$ROOT/deploy/deploy.sh"
check "bind mount: the preflight message explains what to do and that Nginx is not restarted" \
	grep -qF "may reference a replaced copy of \$FRONTEND_DIST, so a publish would not reach it. Reattach the mount before deploying" "$ROOT/deploy/deploy.sh"

# GNU stat takes -c %i; BSD (macOS) stat takes -f %i.
if ! stat -c %i / >/dev/null 2>&1; then
	mkdir -p "$WORK/fakestat"
	printf '#!/bin/sh\nif [ "$1" = -c ] && [ "$2" = %%i ]; then exec /usr/bin/stat -f %%i "$3"; fi\nexec /usr/bin/stat "$@"\n' >"$WORK/fakestat/stat"
	chmod +x "$WORK/fakestat/stat"
fi
inode_of() { stat -c %i "$1" 2>/dev/null || stat -f %i "$1"; }

# identity <host dist> <dir the container sees>: runs dist_mount_matches;
# prints "rc=N" and its messages.
identity() {
	(
		# shellcheck disable=SC2030,SC2031
		PATH="$WORK/fakebin:$PATH"
		if [ -d "$WORK/fakestat" ]; then PATH="$WORK/fakestat:$PATH"; fi
		# Read by the function loaded with eval below.
		# shellcheck disable=SC2034
		FRONTEND_DIST="$1" NGINX_CONTAINER=sbomdelta-nginx NGINX_WEB_ROOT=/usr/share/nginx/html
		export FAKE_WEB_ROOT=/usr/share/nginx/html FAKE_NGINX_DIR="$2"
		# shellcheck disable=SC2317,SC2329
		log() { printf '%s\n' "$*"; }
		eval "$identity_function"
		if dist_mount_matches 2>"$WORK/identity.err"; then rc=0; else rc=$?; fi
		echo "rc=$rc"
		cat "$WORK/identity.err"
	)
}

mkdir -p "$WORK/mount/dist"
echo old-build >"$WORK/mount/dist/index.html"
echo other >"$WORK/mount/other-index.html"
out="$(identity "$WORK/mount/dist" "$WORK/mount/dist")"
check "bind mount: matching directory and index.html pass" [ "$out" = "rc=0" ]
out="$(FAKE_NGINX_INDEX="$WORK/mount/other-index.html" identity "$WORK/mount/dist" "$WORK/mount/dist")"
check "bind mount: a different index.html inode fails" exit_code_is "$out" 1
check "bind mount: ... and names both index.html inodes" \
	contains "$out" "index.html is inode $(inode_of "$WORK/mount/dist/index.html") on the host, but sbomdelta-nginx sees inode $(inode_of "$WORK/mount/other-index.html")"
out="$(FAKE_EXEC_FAIL=1 identity "$WORK/mount/dist" "$WORK/mount/dist")"
check "bind mount: a failing docker exec fails" exit_code_is "$out" 1
check "bind mount: ... saying the inodes could not be read" contains "$out" "could not read the inodes"
out="$(FAKE_EXEC_GARBAGE=1 identity "$WORK/mount/dist" "$WORK/mount/dist")"
check "bind mount: non-numeric output from the container (no stat) fails" exit_code_is "$out" 1
out="$(identity "$WORK/mount/missing" "$WORK/mount/dist")"
check "bind mount: a failing host-side stat fails" contains "$out" "could not read the inodes"

# A replaced directory whose index.html is a hard link to the original file:
# only the directory inodes differ, so this isolates that comparison.
mkdir -p "$WORK/mount/linked"
ln "$WORK/mount/dist/index.html" "$WORK/mount/linked/index.html"
out="$(identity "$WORK/mount/linked" "$WORK/mount/dist")"
check "bind mount: a different directory inode fails even when index.html is the same file" \
	exit_code_is "$out" 1
check "bind mount: ... reporting the directory, not index.html" \
	sh -c 'printf "%s\n" "$1" | grep -q "/linked is inode" && ! printf "%s\n" "$1" | grep -q "index.html is inode"' _ "$out"

# The incident: the container holds the original directory, then the host's
# frontend/dist is replaced by a copy with the same content.
mv "$WORK/mount/dist" "$WORK/mount/dist.original"
mkdir "$WORK/mount/dist"
cp "$WORK/mount/dist.original/index.html" "$WORK/mount/dist/index.html"
out="$(identity "$WORK/mount/dist" "$WORK/mount/dist.original")"
check "bind mount: a replaced directory with identical content fails" exit_code_is "$out" 1
check "bind mount: ... and names both directory inodes" \
	contains "$out" "is inode $(inode_of "$WORK/mount/dist") on the host, but sbomdelta-nginx sees inode $(inode_of "$WORK/mount/dist.original") at /usr/share/nginx/html"

# ------------------------------------------------ frontend publish in place --

# deploy.sh's own backup, publish and restore commands, run on a scratch
# directory: they must update frontend/dist in place (its inode is what the
# Nginx bind mount holds), keep .well-known/ and other files, and prune only
# stale files under assets/.
publish_block="$(awk '
	/^FRONTEND_TOUCHED=1$/ { on = 1 }
	on { print }
	on && /^fi$/ { exit }
' "$ROOT/deploy/deploy.sh")"
backup_cmd="$(grep -m 1 -xF 'tar -C "$FRONTEND_DIST" -czf "$FRONTEND_BACKUP" .' "$ROOT/deploy/deploy.sh" || true)"
check "publish: deploy.sh's publish commands were found" \
	sh -c 'printf "%s\n" "$1" | grep -qF "mv -f \"\$FRONTEND_DIST/.index.html.new\" \"\$FRONTEND_DIST/index.html\"" &&
		printf "%s\n" "$1" | grep -qF "comm -23"' _ "$publish_block"
check "publish: deploy.sh's backup command was found" [ -n "$backup_cmd" ]

# The publish and restore commands run as the directory's owner through
# deploy.sh's own as_dist_owner, under the script's umask 077, with runuser
# standing in as a pass-through. make_dist_readable comes from deploy.sh too.
owner_functions="$(awk '
	/^as_dist_owner\(\) \{/ { print; next }
	/^make_dist_readable\(\) \{$/ { on = 1 }
	on { print }
	on && /^\}$/ { on = 0 }
' "$ROOT/deploy/deploy.sh")"
check "publish: deploy.sh defines as_dist_owner and make_dist_readable" \
	sh -c 'printf "%s\n" "$1" | grep -q "^as_dist_owner() {" && printf "%s\n" "$1" | grep -q "^make_dist_readable() {$"' _ "$owner_functions"
# The definitions before this fix, kept to show the test catches the bug.
legacy_owner_functions='as_dist_owner() { runuser -u "$DIST_OWNER" -- "$@"; }
make_dist_readable() { :; }'
mkdir -p "$WORK/fakerunuser"
printf '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n' >"$WORK/fakerunuser/runuser"
chmod +x "$WORK/fakerunuser/runuser"

mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
# served_readable <dist>: "yes" if a user who is neither owner nor in the
# group (the Nginx worker) can enter the web root and assets/ and read
# index.html, every asset and the other public files at the top of the web
# root; otherwise the first path that fails.
served_readable() {
	local path mode
	while IFS= read -r path; do
		mode="$(mode_of "$path")"
		if [ -d "$path" ]; then
			[ $((8#$mode & 5)) -eq 5 ] || { echo "no:${path#"$1"}=$mode"; return; }
		else
			[ $((8#$mode & 4)) -eq 4 ] || { echo "no:${path#"$1"}=$mode"; return; }
		fi
	done < <({
		echo "$1"
		echo "$1/index.html"
		find "$1" -mindepth 1 -maxdepth 1 -type f ! -name '.*'
		[ ! -d "$1/assets" ] || find "$1/assets"
	})
	echo yes
}

# publish_case <name> <with new assets/ 0|1> [legacy]: builds an old and a new
# frontend, then runs backup, publish and (if it is the expected command)
# restore, printing the state after each. The old frontend starts out as
# production was found: directory 700, files 600, from an earlier run under
# umask 077 -- robots.txt and favicon.ico included, which a restore under that
# umask narrowed too. .well-known/ starts private (750/640), and a hidden
# top-level file and a subdirectory outside assets/ start at 600; all three
# must keep their modes.
publish_case() {
	local pub="$WORK/publish-$1" functions="$owner_functions"
	[ "${3:-}" != legacy ] || functions="$legacy_owner_functions"
	mkdir -p "$pub/dist/assets" "$pub/dist/.well-known/acme-challenge" "$pub/new"
	echo old >"$pub/dist/index.html"
	echo old >"$pub/dist/assets/old-1a2b.js"
	echo shared >"$pub/dist/assets/shared-9f8e.css"
	echo token >"$pub/dist/.well-known/acme-challenge/t"
	echo robots >"$pub/dist/robots.txt"
	echo icon >"$pub/dist/favicon.ico"
	echo private >"$pub/dist/.private"
	mkdir -p "$pub/dist/docs"
	echo notes >"$pub/dist/docs/notes.txt"
	echo new >"$pub/new/index.html"
	if [ "$2" = 1 ]; then
		mkdir -p "$pub/new/assets"
		echo new >"$pub/new/assets/new-3c4d.js"
		echo shared >"$pub/new/assets/shared-9f8e.css"
	fi
	# A fresh build: 755 directories, 644 files.
	find "$pub/new" -type d -exec chmod 755 {} +
	find "$pub/new" -type f -exec chmod 644 {} +
	chmod 700 "$pub/dist" "$pub/dist/assets"
	chmod 600 "$pub/dist/index.html" "$pub/dist/assets/"* "$pub/dist/robots.txt" "$pub/dist/favicon.ico" \
		"$pub/dist/.private" "$pub/dist/docs/notes.txt"
	chmod 700 "$pub/dist/docs"
	chmod 750 "$pub/dist/.well-known" "$pub/dist/.well-known/acme-challenge"
	chmod 640 "$pub/dist/.well-known/acme-challenge/t"
	(
		# The stand-in applies to this subshell only, on purpose.
		# shellcheck disable=SC2030,SC2031
		PATH="$WORK/fakerunuser:$PATH"
		umask 077
		# Read by the commands loaded with eval below.
		# shellcheck disable=SC2034
		FRONTEND_DIST="$pub/dist" NEW_DIST="$pub/new" FRONTEND_BACKUP="$pub/backup.tar.gz"
		# shellcheck disable=SC2034
		DIST_OWNER="$(id -un)"
		eval "$functions"
		# shellcheck disable=SC2317,SC2329
		die() { echo "die: $*"; exit 1; }
		state() {
			printf '%s: dir=%s index=%s old=%s new=%s shared=%s well-known=%s robots=%s\n' "$1" \
				"$([ "$(inode_of "$FRONTEND_DIST")" = "$dir_inode" ] && echo same || echo REPLACED)" \
				"$(cat "$FRONTEND_DIST/index.html")" \
				"$([ -e "$FRONTEND_DIST/assets/old-1a2b.js" ] && echo yes || echo no)" \
				"$([ -e "$FRONTEND_DIST/assets/new-3c4d.js" ] && echo yes || echo no)" \
				"$([ -e "$FRONTEND_DIST/assets/shared-9f8e.css" ] && echo yes || echo no)" \
				"$([ -e "$FRONTEND_DIST/.well-known/acme-challenge/t" ] && echo yes || echo no)" \
				"$([ -e "$FRONTEND_DIST/robots.txt" ] && echo yes || echo no)"
			printf '%s-modes: readable=%s well-known=%s/%s\n' "$1" "$(served_readable "$FRONTEND_DIST")" \
				"$(mode_of "$FRONTEND_DIST/.well-known")" "$(mode_of "$FRONTEND_DIST/.well-known/acme-challenge/t")"
			printf '%s-public: robots=%s favicon=%s\n' "$1" \
				"$(mode_of "$FRONTEND_DIST/robots.txt")" "$(mode_of "$FRONTEND_DIST/favicon.ico")"
			printf '%s-untouched: hidden=%s docs=%s/%s\n' "$1" "$(mode_of "$FRONTEND_DIST/.private")" \
				"$(mode_of "$FRONTEND_DIST/docs")" "$(mode_of "$FRONTEND_DIST/docs/notes.txt")"
		}
		dir_inode="$(inode_of "$FRONTEND_DIST")"
		eval "$backup_cmd"
		eval "$publish_block"
		state published
		if [ "$restore_cmd" = "$expected_restore" ]; then
			# deploy.sh's rollback: the restore, then the same repair.
			eval "$restore_cmd"
			make_dist_readable
			state restored
		fi
	) 2>&1
}

out="$(publish_case assets 1)"
published="$(grep '^published:' <<<"$out" || true)"
restored="$(grep '^restored:' <<<"$out" || true)"
check "publish: frontend/dist is updated in place, with the new index.html" \
	contains "$published" "published: dir=same index=new"
check "publish: stale assets are pruned, current ones kept" contains "$published" "old=no new=yes shared=yes"
check "publish: .well-known/ and files outside assets/ are kept" contains "$published" "well-known=yes robots=yes"
check "restore: frontend/dist stays the same directory, with the old index.html and assets back" \
	contains "$restored" "restored: dir=same index=old old=yes"
check "restore: .well-known/ and files outside assets/ are kept" contains "$restored" "well-known=yes robots=yes"
out="$(publish_case noassets 0)"
check "publish: with no assets/ in the new build, nothing under assets/ is pruned" \
	[ "$(grep '^published:' <<<"$out" || true)" = "published: dir=same index=new old=yes new=no shared=yes well-known=yes robots=yes" ]
check "publish: with no assets/ in the new build, what is served is still readable by Nginx" \
	contains "$out" "published-modes: readable=yes"

# The rollback in deploy.sh must repair the restored frontend the same way,
# and check that / serves the restored index.html rather than the API alone.
rollback_function="$(awk '/^rollback\(\) \{$/ { on = 1 } on { print } on && /^\}$/ { exit }' "$ROOT/deploy/deploy.sh")"
check "rollback: make_dist_readable runs right after the frontend restore" \
	sh -c 'printf "%s\n" "$1" | grep -A 3 -F "$2" | grep -q "make_dist_readable"' _ "$rollback_function" "$expected_restore"
check "rollback: the final check passes the restored index.html checksum" \
	grep -qF 'wait_for_nginx "$restored_sha"' <<<"$rollback_function"

# deploy.sh's own rollback, with the services untouched and stand-ins for the
# owner's commands and the smoke test. The stand-in smoke test passes on the
# API alone when given no checksum, which is exactly how a failed frontend
# restore could pass for a healthy site.
# rollback_case <name> <frontend touched 0|1> <restore works 0|1> <homepage serves the restored index.html 0|1>
rollback_case() {
	local rb="$WORK/rollback-$1"
	mkdir -p "$rb/dist" "$rb/saved"
	echo published >"$rb/dist/index.html"
	echo restored >"$rb/saved/index.html"
	tar -C "$rb/saved" -czf "$rb/backup.tar.gz" .
	(
		# Read by the function loaded with eval below.
		# shellcheck disable=SC2034
		FRONTEND_TOUCHED="$2" FRONTEND_DIST="$rb/dist" FRONTEND_BACKUP="$rb/backup.tar.gz" \
			SERVER_SWITCHED=0 WORKER_SWITCHED=0 WORKER_PRESENT=1 ROLLING_BACK=0 DB_BACKUP=""
		RESTORE_WORKS="$3" HOME_SERVES="$4"
		WANT="$(sha256sum <"$rb/saved/index.html" | cut -d' ' -f1)"
		# shellcheck disable=SC2317,SC2329
		log() { printf '%s\n' "$*"; }
		# shellcheck disable=SC2317,SC2329
		as_dist_owner() { [ "$RESTORE_WORKS" = 1 ] || { echo "tar: stand-in failure" >&2; return 1; }; "$@"; }
		# shellcheck disable=SC2317,SC2329
		make_dist_readable() { :; }
		# shellcheck disable=SC2317,SC2329
		wait_for_nginx() {
			echo "smoke: checksum=${1:-none}"
			[ -n "${1:-}" ] || return 0
			[ "$HOME_SERVES" = 1 ] && [ "$1" = "$WANT" ]
		}
		eval "$rollback_function"
		rollback
		echo "rollback returned"
	) 2>&1
}
restored_want="$(printf 'restored\n' | sha256sum | cut -d' ' -f1)"

out="$(rollback_case restore-fails 1 0 1)"
check "rollback, restore fails: the failure is logged" contains "$out" "ROLLBACK: frontend restore FAILED"
check "rollback, restore fails: the homepage is reported UNVERIFIED" contains "$out" "the frontend was NOT restored, so the homepage is UNVERIFIED"
check "rollback, restore fails: no message claims the site or homepage is healthy" \
	sh -c '! printf "%s\n" "$1" | grep -qE "the site answers through Nginx|serves the restored index.html"' _ "$out"
check "rollback, restore fails: the rest of the rollback still runs (best effort)" contains "$out" "rollback returned"
out="$(rollback_case restore-works 1 1 1)"
check "rollback, restore works: the homepage is checked against the restored index.html" \
	contains "$out" "smoke: checksum=$restored_want"
check "rollback, restore works: success names the restored index.html" \
	contains "$out" "the site answers through Nginx and serves the restored index.html"
out="$(rollback_case homepage-wrong 1 1 0)"
check "rollback, restored but / does not serve it: reported as a failure" \
	contains "$out" "ROLLBACK: the site does NOT answer through Nginx; investigate immediately"
out="$(rollback_case no-frontend 0 1 1)"
check "rollback, frontend never touched: only the API is checked, and no homepage claim is made" \
	sh -c 'printf "%s\n" "$1" | grep -q "smoke: checksum=none" && printf "%s\n" "$1" | grep -qx "ROLLBACK: the site answers through Nginx"' _ "$out"

# The incident: under umask 077 the owner's tar and cp left the web root,
# assets and index.html readable by the owner only, and Nginx answered 403.
out="$(publish_case modes 1)"
check "permissions: after publish, Nginx can enter the web root and assets/ and read every served file" \
	contains "$out" "published-modes: readable=yes"
check "permissions: after publish, .well-known/ keeps its own modes" contains "$out" "published-modes: readable=yes well-known=750/640"
check "permissions: after restore, the restored frontend is readable by Nginx" \
	contains "$out" "restored-modes: readable=yes"
check "permissions: after restore, .well-known/ keeps its own modes" contains "$out" "restored-modes: readable=yes well-known=750/640"
check "permissions: after publish, top-level robots.txt and favicon.ico are readable by Nginx" \
	contains "$out" "published-public: robots=644 favicon=644"
check "permissions: after restore, top-level robots.txt and favicon.ico are readable by Nginx" \
	contains "$out" "restored-public: robots=644 favicon=644"
check "permissions: after publish, hidden files and subdirectories outside assets/ keep their modes" \
	contains "$out" "published-untouched: hidden=600 docs=700/600"
check "permissions: after restore, hidden files and subdirectories outside assets/ keep their modes" \
	contains "$out" "restored-untouched: hidden=600 docs=700/600"
out="$(publish_case legacy 1 legacy)"
check "permissions: the previous as_dist_owner leaves the frontend unreadable (the test catches the bug)" \
	sh -c 'printf "%s\n" "$1" | grep -q "^published-modes: readable=no"' _ "$out"

# ------------------------------------------------ Nginx smoke diagnostics --

# deploy.sh's smoke test, against a stand-in curl that answers /api/repos and
# / from files. A failure must say which check failed: an API fault, a
# homepage status (the 403 of the incident) and a stale homepage each point
# somewhere different, and the old message blamed the frontend for all three.
smoke_functions="$(awk '
	/^(nginx_get|smoke_nginx|wait_for_nginx)\(\) \{$/ { on = 1 }
	on { print }
	on && /^\}$/ { on = 0 }
' "$ROOT/deploy/deploy.sh")"
check "smoke: deploy.sh defines nginx_get, smoke_nginx and wait_for_nginx" \
	[ "$(grep -cE '^(nginx_get|smoke_nginx|wait_for_nginx)\(\) \{$' <<<"$smoke_functions")" -eq 3 ]

mkdir -p "$WORK/fakecurl" "$WORK/smoke"
cat >"$WORK/fakecurl/curl" <<'EOF2'
#!/usr/bin/env bash
# curl -sS -o <file> -w '%{http_code}' --max-time N --resolve H:P:IP <url>
out="" url=""
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out="$2"; shift 2 ;;
	-w | --max-time | --resolve) shift 2 ;;
	-*) shift ;;
	*) url="$1"; shift ;;
	esac
done
case "$url" in
*/api/repos) cat "$FAKE_API_BODY" >"$out"; printf '%s' "${FAKE_API_CODE:-200}" ;;
*/) cat "$FAKE_HOME_BODY" >"$out"; printf '%s' "${FAKE_HOME_CODE:-200}" ;;
*) echo "fake curl: unexpected url $url" >&2; exit 2 ;;
esac
EOF2
chmod +x "$WORK/fakecurl/curl"
printf '{"repositories":[]}' >"$WORK/smoke/api-ok"
printf '{"error":"x"}' >"$WORK/smoke/api-other"
echo '<html>new</html>' >"$WORK/smoke/index-new"
echo '<html>old</html>' >"$WORK/smoke/index-old"
new_sha="$(sha256sum <"$WORK/smoke/index-new" | cut -d' ' -f1)"
old_sha="$(sha256sum <"$WORK/smoke/index-old" | cut -d' ' -f1)"

# smoke <expected sha or empty>: runs wait_for_nginx with the stand-in curl
# and no real sleeping; prints its log lines and "rc=N".
smoke() {
	(
		# shellcheck disable=SC2030,SC2031
		PATH="$WORK/fakecurl:$PATH"
		# Read by the functions loaded with eval below.
		# shellcheck disable=SC2034
		PUBLIC_HOST=sbomdelta.example NGINX_HTTPS_PORT=443 NGINX_HTTPS_IP=127.0.0.1 SMOKE_PROBLEM=""
		export FAKE_API_BODY="${FAKE_API_BODY:-$WORK/smoke/api-ok}" FAKE_HOME_BODY="${FAKE_HOME_BODY:-$WORK/smoke/index-new}"
		# shellcheck disable=SC2317,SC2329
		log() { printf '%s\n' "$*"; }
		# shellcheck disable=SC2317,SC2329
		sleep() { :; }
		eval "$smoke_functions"
		if wait_for_nginx "$1"; then echo rc=0; else echo rc=1; fi
	)
}

out="$(smoke "$new_sha")"
check "smoke: API and homepage both right passes" [ "$out" = "rc=0" ]
out="$(smoke "")"
check "smoke: without a checksum only the API is checked" [ "$out" = "rc=0" ]
out="$(FAKE_API_CODE=502 smoke "$new_sha")"
check "smoke: an API failure fails" exit_code_is "$out" 1
check "smoke: ... and names /api/repos and its status, not the homepage" \
	sh -c 'printf "%s\n" "$1" | grep -q "last: /api/repos returned HTTP 502" && ! printf "%s\n" "$1" | grep -q homepage' _ "$out"
out="$(FAKE_API_BODY="$WORK/smoke/api-other" smoke "$new_sha")"
check "smoke: an API answer without a repositories list is named as such" \
	contains "$out" "last: /api/repos returned 200 without a repositories list"
out="$(FAKE_HOME_CODE=403 smoke "$new_sha")"
check "smoke: a homepage 403 (the incident) fails" exit_code_is "$out" 1
check "smoke: ... and names the homepage status" contains "$out" "last: the homepage (/) returned HTTP 403"
out="$(FAKE_HOME_CODE=403 smoke "")"
check "smoke: a homepage 403 goes unseen without a checksum (why rollback now passes one)" [ "$out" = "rc=0" ]
out="$(FAKE_HOME_BODY="$WORK/smoke/index-old" smoke "$new_sha")"
check "smoke: a stale homepage fails, naming both checksums" \
	contains "$out" "last: the homepage (/) served index.html sha256 $old_sha, expected $new_sha"
check "smoke: ... after all 10 attempts" contains "$out" "failed 10 times"
check "smoke: response bodies are never printed" \
	sh -c '! printf "%s\n" "$1" | grep -q "<html>"' _ "$out"

# ------------------------------------------------------- worker image --

# With no worker container, deploy.sh takes the worker's image from the
# production Compose file. `compose config --images worker` also lists the
# images of everything the worker depends on (the cause of a failed preflight),
# so service_image must still find exactly the worker's own image.
image_function="$(awk '/^service_image\(\) \{$/ { on = 1 } on { print } on && /^\}$/ { on = 0 }' "$ROOT/deploy/deploy.sh")"
check "worker image: deploy.sh defines service_image" grep -q '^service_image() {$' <<<"$image_function"

# image_of <compose-file|-> <service>: runs service_image in a subshell, with
# compose() pointing at the file, or at the stand-in below for "-".
image_of() {
	(
		# compose() is called by the service_image loaded with eval below.
		# shellcheck disable=SC2317,SC2329
		if [ "$1" = - ]; then
			compose() { fake_compose "$@"; }
		else
			compose_file="$1"
			# shellcheck disable=SC2317,SC2329
			compose() { docker compose --project-directory "$(dirname "$compose_file")" -f "$compose_file" -p sbomdelta "$@"; }
		fi
		eval "$image_function"
		if out="$(service_image "$2")"; then rc=0; else rc=$?; fi
		printf 'rc=%s lines=%s image=%s\n' "$rc" "$(printf '%s\n' "$out" | grep -c . || true)" "$(printf '%s' "$out" | tr '\n' ' ')"
	)
}

if docker compose version >/dev/null 2>&1; then
	mkdir -p "$WORK/compose"
	# compose_case <name> <worker definition> [extra services]: a project shaped
	# like production -- build-only server and worker, the worker depending on
	# postgres, minio and server, and nginx depending on server.
	compose_case() {
		mkdir -p "$WORK/compose/$1"
		cat >"$WORK/compose/$1/docker-compose.yml" <<EOF
services:
  postgres:
    image: postgres:16-alpine
  minio:
    image: minio/minio:latest
  server:
    build: { context: ., target: server }
    depends_on:
      postgres: { condition: service_healthy }
      minio: { condition: service_healthy }
  worker:
$2
  nginx:
    image: nginx:alpine
    container_name: sbomdelta-nginx
    depends_on: [server]
${3:-}
EOF
		printf '%s\n' "$WORK/compose/$1/docker-compose.yml"
	}
	deps='    depends_on:
      postgres: { condition: service_healthy }
      minio: { condition: service_healthy }
      server: { condition: service_started }'

	f="$(compose_case prod "    build: { context: ., target: worker }
$deps")"
	check "worker image: the bare 'config --images worker' lists more than the worker (the original failure)" \
		[ "$(docker compose --project-directory "$(dirname "$f")" -f "$f" -p sbomdelta config --images worker | grep -c .)" -gt 1 ]
	check "worker image: a build-only worker with dependencies resolves to sbomdelta-worker" \
		[ "$(image_of "$f" worker)" = "rc=0 lines=1 image=sbomdelta-worker" ]
	f="$(compose_case explicit "    image: registry.example/sbomdelta-worker:prod
    build: { context: ., target: worker }
$deps")"
	check "worker image: an explicit image name is used" \
		[ "$(image_of "$f" worker)" = "rc=0 lines=1 image=registry.example/sbomdelta-worker:prod" ]
	f="$(compose_case nodeps "    build: { context: ., target: worker }")"
	check "worker image: a worker with no dependencies resolves" \
		[ "$(image_of "$f" worker)" = "rc=0 lines=1 image=sbomdelta-worker" ]
	f="$(compose_case shared "    image: postgres:16-alpine
$deps")"
	check "worker image: an image shared with another service resolves to nothing (refused)" \
		contains "$(image_of "$f" worker)" "lines=0"
	f="$(compose_case dependent "    build: { context: ., target: worker }
$deps" "  watcher:
    image: busybox
    depends_on: [worker]")"
	check "worker image: a service depending on the worker leaves nothing (refused, not guessed)" \
		contains "$(image_of "$f" worker)" "lines=0"
	f="$(compose_case broken "    build: [this is not valid")"
	check "worker image: an unparsable Compose file is an error" exit_code_is "$(image_of "$f" worker)" 1
elif [ "$in_ci" -eq 1 ]; then
	fail "worker image: docker compose is not available in CI"
else
	echo "skip worker image (real Compose): docker compose is not available"
fi

# Stand-in Compose behaviours. "ignore-names" prints every image whatever is
# asked, which must not yield a guess; the "fail-*" modes make one of the
# image queries fail, which must be an error rather than a partial answer.
# shellcheck disable=SC2317,SC2329
fake_compose() {
	case "${FAKE_COMPOSE_MODE:-}:$*" in
	*:"config --services") printf '%s\n' postgres minio server worker nginx ;;
	fail-own:"config --images worker") return 1 ;;
	fail-own:"config --images "*) printf '%s\n' sbomdelta-server postgres:16-alpine minio/minio:latest nginx:alpine ;;
	fail-others:"config --images worker") printf '%s\n' sbomdelta-server sbomdelta-worker postgres:16-alpine minio/minio:latest ;;
	fail-others:"config --images "*) return 1 ;;
	ignore-names:"config --images "*) printf '%s\n' sbomdelta-server sbomdelta-worker nginx:alpine postgres:16-alpine minio/minio:latest ;;
	*) return 1 ;;
	esac
}
check "worker image: a Compose that ignores service names resolves to nothing (refused)" \
	contains "$(FAKE_COMPOSE_MODE=ignore-names image_of - worker)" "lines=0"
check "worker image: a failing query for the worker's images is an error" \
	exit_code_is "$(FAKE_COMPOSE_MODE=fail-own image_of - worker)" 1
check "worker image: a failing query for the other services' images is an error" \
	exit_code_is "$(FAKE_COMPOSE_MODE=fail-others image_of - worker)" 1

# ------------------------------------------------- destructive-command guard --

guard="$ROOT/deploy/tests/check-destructive.sh"
check "guard: the deployment path is clean" "$guard" >/dev/null
while IFS= read -r line; do
	[ -n "$line" ] || continue
	printf '%s\n' "$line" >"$WORK/bad.sh"
	check "guard catches: $line" sh -c '! "$1" "$2" >/dev/null' _ "$guard" "$WORK/bad.sh"
done <<'EOF'
docker compose -p x down
docker compose -f a.yml -p x down -v
compose rm -f server
docker compose stop worker
docker rm -f abc
docker volume rm sbomdelta_postgres-data
docker volume prune -f
docker container prune
docker system prune --volumes
docker image rm app:latest
git clean -xfd
git reset --hard origin/main
git push origin main
git checkout -f main
rm -rf /home/ec2-user/SBOMDelta
x && rm -r dist
psql -c "DROP TABLE repositories"
psql -c "truncate table jobs"
psql -c "DELETE FROM scans"
psql -c "ALTER TABLE scans DROP COLUMN x"
dropdb sbomdelta
pg_restore --clean -d sbomdelta backup.dump
truncate -s 0 /var/log/x
EOF
while IFS= read -r line; do
	[ -n "$line" ] || continue
	printf '%s\n' "$line" >"$WORK/ok.sh"
	check "guard allows: $line" "$guard" "$WORK/ok.sh"
done <<'EOF'
docker rmi "$SERVER_REPO:$NEW_TAG"
docker exec -i "$PG_CID" pg_restore --list <"$DB_BACKUP"
xargs -r rm -f --
compose up -d --no-deps --no-build server
# a comment may say docker compose down
EOF

echo
if [ "$failures" -ne 0 ]; then
	echo "$failures test(s) failed"
	exit 1
fi
echo "all deployment script tests passed"
