#!/usr/bin/env bash
# ci-step.sh — the shell every `run:` step of .github/workflows/ci.yml runs
# under, and what each job's last step runs to say why the job failed.
#
#   bash scripts/ci-step.sh SCRIPT   run a step's SCRIPT the way GitHub would,
#                                    recording its output and exit status
#   bash scripts/ci-step.sh --why    annotate the job's failed steps
#
# Why: a job log needs admin rights on the repository to read (GET
# .../actions/jobs/{id}/logs answers 403 without them), while a check run's
# annotations are public. A red job's only annotation was "Process completed
# with exit code 1.", so from a machine without a token a failure could only
# be guessed at, or reproduced (Task 20444). Each step's output is recorded
# here as it streams to the log, and when a job fails its last step hands the
# record to scripts/ci-annotate, which annotates the cause: each failing
# test, panic, data race, timeout, build or vet failure in go's output, or
# else the failed step's last lines. scripts/ci-why.sh reads them back.
#
# ci.yml names the first form as defaults.run.shell, so nothing about a step
# changes but that its output is also written to a file: its script runs
# under `bash -e`, the command GitHub runs for a step that names no shell; its
# output reaches the log as it is written; it gets the same environment, plus
# CI_WHY_STEP_DIR; and the step exits with the script's status, whatever
# happens to the record.
#
# The record, under $CI_WHY_DIR (default $RUNNER_TEMP/ci-why), one numbered
# directory per step in the order the steps ran:
#   script   the step's script
#   log      everything it printed, stdout and stderr in the order written
#   status   its exit status, written when it ended; a step with none was
#            killed (its timeout-minutes, or a cancelled run)
#   annotated  written by ci-annotate when the step annotated itself, so the
#            last step leaves it be
set -u

dir=${CI_WHY_DIR:-${RUNNER_TEMP:-/tmp}/ci-why}
level=${CI_WHY_LEVEL:-error}

# escape_data and escape_property escape a workflow command's message and
# property values as the runner unescapes them (%, CR, LF; and ':' and ','
# in a property), dropping terminal colour codes on the way.
escape_data() {
	LC_ALL=C sed -e 's#\x1b\[[0-9;?]*[ -/]*[@-~]##g' |
		awk 'BEGIN { ORS = "" } { gsub(/%/, "%25"); gsub(/\r/, "%0D"); if (NR > 1) print "%0A"; print }'
}

escape_property() {
	printf '%s' "$1" | escape_data | sed -e 's/:/%3A/g' -e 's/,/%2C/g'
}

# first_command is the first line of a step's script that does something.
first_command() {
	grep -m 1 -vE '^[[:space:]]*(#|$|set[[:space:]]|shopt[[:space:]])' "$1" 2>/dev/null |
		sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*\\$//' |
		awk '{ if (length($0) > 80) print substr($0, 1, 79) "…"; else print }'
}

# tail_why annotates each failed step with its last forty lines: what this
# falls back to when Go cannot run scripts/ci-annotate.
tail_why() {
	local step status what
	for step in "$dir"/[0-9]*; do
		[ -d "$step" ] || continue
		[ "$step" = "${CI_WHY_STEP_DIR:-}" ] && continue
		[ -e "$step/annotated" ] && continue
		status=$(cat "$step/status" 2>/dev/null) || status=
		[ "$status" = 0 ] && continue
		if [ -n "$status" ]; then
			what="A step exited $status: $(first_command "$step/script")"
		else
			what="A step was killed before it finished (its timeout-minutes, or a cancelled run): $(first_command "$step/script")"
		fi
		printf '::%s title=%s::%s\n' "$level" "$(escape_property "$what")" \
			"$(tail -n 40 "$step/log" 2>/dev/null | escape_data)"
	done
}

why() {
	if [ ! -d "$dir" ]; then
		echo "ci-step: no step of this job was recorded ($dir does not exist)"
		return 0
	fi
	# scripts/ci-annotate knows go's output; a job that never set Go up
	# still has the runner's, which fetches the toolchain go.mod names. Bounded
	# so that a fetch that hangs cannot hold the job.
	if [ -z "${CI_WHY_NO_GO:-}" ] && command -v go > /dev/null 2>&1 &&
		timeout 600 go run ./scripts/ci-annotate -level "$level" -steps "$dir"; then
		return 0
	fi
	echo "ci-step: scripts/ci-annotate did not run; annotating each failed step's last lines"
	tail_why
}

if [ "${1:-}" = --why ]; then
	why
	exit 0
fi

script=${1:?usage: ci-step.sh SCRIPT | ci-step.sh --why}

# A directory per step, numbered in the order the steps ran: mkdir is the
# allocation, and fails on a number already taken. If there is nowhere to
# record, the step runs unrecorded — a record is never worth a verdict.
step=
if mkdir -p "$dir" 2> /dev/null && command -v tee > /dev/null; then
	for ((n = 1; n < 1000; n++)); do
		if mkdir "$dir/$(printf '%03d' "$n")" 2> /dev/null; then
			step=$dir/$(printf '%03d' "$n")
			break
		fi
	done
fi
if [ -z "$step" ]; then
	exec bash -e "$script"
fi
cp "$script" "$step/script" 2> /dev/null || true
export CI_WHY_STEP_DIR=$step

# tee copies the output to the log as it is written. The script's own copy
# of the pipe is the only one it holds (3>&- closes the wrapper's), so tee
# ends when the script and whatever it started have finished writing.
exec 3> >(exec tee "$step/log")
tee_pid=$!
bash -e "$script" >&3 2>&3 3>&-
status=$?
exec 3>&-
printf '%s\n' "$status" > "$step/status" 2> /dev/null || true
# Let tee write out the last of the output, but not for long: a process the
# step left running in the background holds the pipe until it exits, and
# GitHub itself waits five seconds for that before it moves on.
for ((i = 0; i < 30; i++)); do
	kill -0 "$tee_pid" 2> /dev/null || break
	sleep 0.1
done
exit "$status"
