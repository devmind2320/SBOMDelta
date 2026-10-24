# shellcheck shell=sh
# bootstrap.sh -- first stage of a deployment, run as root through AWS SSM.
#
# The CD workflow sends this file as the SSM command, preceded by plain
# assignments of DEPLOY_DIR, SHA, MODE, SKIP_OLDER and CI_OVERRIDE, each
# validated by the workflow. SSM runs it with /bin/sh, so it is POSIX sh.
#
# It takes the host's deployment lock before it reads or changes anything,
# moves the deployment checkout to SHA, and then runs deploy/deploy.sh as it
# exists in that commit, from a private copy, still holding the lock. The lock
# matters because cancelling a workflow run does not stop its SSM command:
# without it, the next run could check out another commit underneath a
# deployment that is still building from the checkout.

set -eu
umask 077

LOCK_FILE="${LOCK_FILE:-/run/lock/sbomdelta-deploy.lock}"
SCRATCH_DIR="${SCRATCH_DIR:-/run}"
SKIP_OLDER="${SKIP_OLDER:-0}"
CI_OVERRIDE="${CI_OVERRIDE:-0}"

fail() { echo "bootstrap: $*"; exit 1; }

case "${SHA:-}" in
*[!0-9a-f]* | "") fail "SHA must be a full lowercase commit id" ;;
esac
[ "${#SHA}" -eq 40 ] || fail "SHA must be a full lowercase commit id"
case "${MODE:-}" in
preflight | deploy) ;;
*) fail "MODE must be preflight or deploy" ;;
esac
case "${DEPLOY_DIR:-}" in
/*) ;;
*) fail "DEPLOY_DIR must be an absolute path" ;;
esac
[ -d "$DEPLOY_DIR" ] || fail "deployment checkout $DEPLOY_DIR does not exist"

# The lock comes first. Descriptor 9 stays open across the exec below, so
# deploy.sh holds this same lock until it exits.
exec 9>>"$LOCK_FILE"
if ! flock -n 9; then
	echo "bootstrap: another deployment is running on this host ($LOCK_FILE is held); nothing was changed"
	exit 75
fi

# Git runs as the checkout's owner, so root never writes into it.
OWNER="$(stat -c %U "$DEPLOY_DIR" 2>/dev/null || stat -f %Su "$DEPLOY_DIR")"
if [ "$(id -u)" = "$(id -u "$OWNER")" ]; then
	as_owner() { git -C "$DEPLOY_DIR" "$@"; }
else
	OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
	as_owner() { runuser -u "$OWNER" -- env HOME="$OWNER_HOME" git -C "$DEPLOY_DIR" "$@"; }
fi

as_owner rev-parse --is-inside-work-tree >/dev/null || fail "$DEPLOY_DIR is not a git checkout"
[ -z "$(as_owner status --porcelain --untracked-files=no)" ] ||
	fail "deployment checkout has local changes to tracked files"
as_owner fetch --quiet --no-tags origin main
as_owner merge-base --is-ancestor "$SHA" FETCH_HEAD || fail "$SHA is not on origin/main"
as_owner -c advice.detachedHead=false checkout --quiet --detach "$SHA"
[ "$(as_owner rev-parse HEAD)" = "$SHA" ] || fail "checkout did not land on $SHA"

# Bash reads a script as it runs it, so deploy.sh runs from a private copy of
# the committed file rather than from the checkout. deploy.sh removes the copy
# when it exits.
COPY_DIR="$(mktemp -d "$SCRATCH_DIR/sbomdelta-deploy.XXXXXX")"
as_owner show "$SHA:deploy/deploy.sh" >"$COPY_DIR/deploy.sh" || fail "$SHA has no deploy/deploy.sh"

set -- --sha "$SHA" --mode "$MODE" --deploy-dir "$DEPLOY_DIR"
if [ "$SKIP_OLDER" = 1 ]; then set -- "$@" --skip-if-older; fi
if [ "$CI_OVERRIDE" = 1 ]; then set -- "$@" --ci-override; fi
exec env DEPLOY_DIR="$DEPLOY_DIR" DEPLOY_LOCK_FILE="$LOCK_FILE" DEPLOY_SCRIPT_COPY="$COPY_DIR/deploy.sh" \
	bash "$COPY_DIR/deploy.sh" "$@"
