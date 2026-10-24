#!/usr/bin/env bash
# ssm-result.sh -- check the result marker in a deployment's instance output.
#
# deploy.sh ends every successful run with exactly one line:
#   SBOMDELTA_RESULT status=preflight-ok  sha=<sha>
#   SBOMDELTA_RESULT status=skipped-older sha=<sha> deployed=<sha>
#   SBOMDELTA_RESULT status=deployed      sha=<sha> index_sha256=<sha256>
# The CD workflow pipes the instance output through this script and requires
# a marker that fits the run. A missing marker fails the run, whatever the
# reason (SSM keeps only the first 24,000 characters of output), so the
# frontend check is never skipped by accident.
#
# Usage: ssm-result.sh <mode> <sha> <allow-skip 0|1> < instance-output
# Prints "result=..." and "index_sha=..." lines for $GITHUB_OUTPUT.

set -euo pipefail

mode="${1:?mode}" sha="${2:?sha}" allow_skip="${3:?allow-skip}"

markers="$(grep -E '^SBOMDELTA_RESULT ' || true)"
count="$(printf '%s' "$markers" | grep -c . || true)"
if [ "$count" -ne 1 ]; then
	echo "::error::expected one result marker in the instance output, found $count (output may be truncated)" >&2
	exit 1
fi

field() { sed -nE "s/.*[[:space:]]$1=([^[:space:]]+).*/\\1/p" <<<"$markers"; }
status="$(field status)"
marker_sha="$(field sha)"
index_sha="$(field index_sha256)"

if [ "$marker_sha" != "$sha" ]; then
	echo "::error::result marker is for '$marker_sha', not $sha" >&2
	exit 1
fi

case "$mode:$status" in
preflight:preflight-ok) ;;
deploy:deployed)
	if ! [[ "$index_sha" =~ ^[0-9a-f]{64}$ ]]; then
		echo "::error::deployed result has no valid index_sha256" >&2
		exit 1
	fi
	;;
deploy:skipped-older)
	if [ "$allow_skip" != 1 ]; then
		echo "::error::the instance skipped $sha, but this run did not allow skipping" >&2
		exit 1
	fi
	index_sha=""
	;;
*)
	echo "::error::result '$status' does not fit mode '$mode'" >&2
	exit 1
	;;
esac

echo "result=$status"
echo "index_sha=$index_sha"
