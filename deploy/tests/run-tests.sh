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
