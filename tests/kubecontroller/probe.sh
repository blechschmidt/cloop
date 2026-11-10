#!/bin/sh
# The check a task runs inside a runner Pod (tests/kubecontroller, Task 20487).
#
# The stand-in claude (scripts/e2e/gitproxy/claude) decodes this from the task
# description and runs it in the run's working directory. pool_test.go fills
# in the __PLACEHOLDERS__ per task. Each check prints one line,
# "RESULT <ID> PASS|FAIL <detail>", and nothing else is printed: `cloop run`
# keeps only the first and last lines of a harness's output.
#
# The steps, in the order the mode names them:
#   isolation  nothing another project's runs left is on this volume (I1–I3)
#   seed       leave a file and a git commit in the workspace (S1)
#   reuse      the file and the commit a previous run left are here (P1, P2)
#   hold       run until the test creates the release file (H0, H1)
#
# Nothing here may spell a credential's prefix: the test scans every volume
# for those afterwards, and this script is kept, inside the task, in the
# project state the run leaves on its volume.

mode='__MODE__'
root='__ROOT__'
mark='__MARK__'
# The marker's content and every commit id are written in two halves, so this
# text never holds one whole: an isolation check must find another project's
# data, not the description of it.
content='__CONTENT_A__''__CONTENT_B__'

say() { echo "RESULT $*"; }

case "$PWD" in
"$root"/workspace/*) say ENV PASS "pwd=$PWD uid=$(id -u)" ;;
*) say ENV FAIL "pwd=$PWD uid=$(id -u): the workspace is not on the runner's volume" ;;
esac

for step in $mode; do
	case "$step" in
	isolation)
		mine=$(basename "$PWD")
		found=""
		for m in __OTHER_MARKS__; do
			found="$found$(find "$root" -name "$m*" 2>/dev/null | head -n 3 | tr '\n' ' ')"
		done
		if [ -z "$found" ]; then say I1 PASS "no other project's file"; else say I1 FAIL "found $found"; fi
		others=$(ls -A "$root/workspace" 2>/dev/null | grep -vx "$mine" | tr '\n' ' ')
		if [ -z "$others" ]; then say I2 PASS "only $mine"; else say I2 FAIL "other trees: $others"; fi
		objs=""
		for o in __OTHER_OBJECTS__; do
			for d in $(find "$root" -type d -name objects 2>/dev/null); do
				if [ -e "$d/$o" ]; then objs="$objs $d/$o"; fi
			done
		done
		if [ -z "$objs" ]; then say I3 PASS "no other project's git object"; else say I3 FAIL "found$objs"; fi
		;;
	seed)
		if ! printf '%s\n' "$content" >"$mark"; then
			say S1 FAIL "cannot write $mark"
			continue
		fi
		git init -q . 2>/dev/null
		if git -c user.name=e2e -c user.email=e2e@cloop.invalid add -- "$mark" &&
			git -c user.name=e2e -c user.email=e2e@cloop.invalid commit -q -m "$mark" -- "$mark"; then
			say S1 PASS "commit=$(git rev-parse HEAD)"
		else
			say S1 FAIL "git commit failed"
		fi
		;;
	reuse)
		got=$(cat "$mark" 2>/dev/null)
		if [ "$got" = "$content" ]; then say P1 PASS "$mark kept"; else say P1 FAIL "$mark reads '$got'"; fi
		sha='__SHA_A__''__SHA_B__'
		if git cat-file -e "$sha^{commit}" 2>/dev/null && [ "$(git log -1 --format=%s 2>/dev/null)" = "$mark" ]; then
			say P2 PASS "commit $sha kept"
		else
			say P2 FAIL "commit $sha is gone (head: $(git log -1 --format=%H 2>/dev/null))"
		fi
		;;
	hold)
		say H0 PASS "holding"
		i=0
		while [ ! -e '__RELEASE__' ] && [ "$i" -lt 900 ]; do
			sleep 1
			i=$((i + 1))
		done
		if [ -e '__RELEASE__' ]; then say H1 PASS "released after ${i}s"; else say H1 FAIL "never released"; fi
		;;
	*)
		say MODE FAIL "unknown step $step"
		;;
	esac
done
