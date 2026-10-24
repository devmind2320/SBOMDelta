#!/usr/bin/env bash
# check-destructive.sh -- fail if the deployment path contains a command that
# destroys containers, volumes, data or history.
#
# These files run as root against production, so the list is deliberately
# blunt: a line that needs one of these phrases in prose must be a comment.
# Lines whose first non-blank character is # are not checked. Add a pattern
# here, with a must-catch case in run-tests.sh, rather than special-casing it.
#
# Usage: check-destructive.sh [file...]   (default: the deployment path)

set -euo pipefail

cd "$(dirname "$0")/../.."
if [ $# -gt 0 ]; then
	files=("$@")
else
	files=(deploy/deploy.sh deploy/bootstrap.sh .github/workflows/cd.yml)
fi

# Extended regular expressions, matched case-insensitively, one per line.
patterns="$(
	cat <<'EOF'
compose([[:space:]].*)?[[:space:]](down|rm|stop|kill|pause)([[:space:]]|$)
docker[[:space:]]+(rm|kill|stop)([[:space:]]|$)
docker[[:space:]]+(container|volume|network|image|system|builder|buildx)[[:space:]]+(rm|remove|prune)
docker[[:space:]].*[[:space:]]prune([[:space:]]|$)
--volumes
volume[[:space:]]+rm
git[[:space:]]+(clean|push|stash)
git[[:space:]]+reset[[:space:]]+--hard
git[[:space:]]+(checkout|switch)[[:space:]].*(-f|--force)([[:space:]]|$)
(^|[[:space:];|&])rm[[:space:]]+(-[a-z]*r|--recursive)
(drop|truncate)[[:space:]]+(table|database|schema|index|view|role|user|owned)
alter[[:space:]]+table.*[[:space:]]drop[[:space:]]
delete[[:space:]]+from
(^|[[:space:];|&])(dropdb|dropuser)([[:space:]]|$)
pg_restore.*(--clean|--dbname|[[:space:]]-c([[:space:]]|$)|[[:space:]]-d[[:space:]])
(^|[[:space:];|&])truncate[[:space:]]+-s
EOF
)"

status=0
for file in "${files[@]}"; do
	if matches="$(grep -nEi -f <(printf '%s\n' "$patterns") "$file" | grep -vE '^[0-9]+:[[:space:]]*#')"; then
		printf '%s\n' "$matches" | sed "s#^#$file:#"
		status=1
	fi
done
if [ "$status" -ne 0 ]; then
	echo "::error::destructive command found in the deployment path"
fi
exit "$status"
