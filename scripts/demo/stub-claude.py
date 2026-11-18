#!/usr/bin/env python3
"""stub-claude.py — Claude Code's stand-in while the demo is recorded.

record-fixtures.sh copies this file to <scratch>/bin/claude, beside
projects.py, and puts that directory first on the hub's PATH, so the
claudecode provider runs it exactly as it runs Claude Code: the prompt on
stdin, the project as the working directory, the outbox for attachments in
$CLOOP_TASK_ATTACHMENTS. It does what projects.py says the task's turn does —
writes the files and commits them, attaches a report, fails once, or runs out
of usage — and prints what the agent says, ending with the signal cloop reads.

It also answers the two questions the hub asks the CLI itself:
`claude --version` and `claude auth status --json`. Nothing here calls out.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import projects  # noqa: E402  (beside this file)


def main(argv: list[str]) -> int:
    if "--version" in argv or argv[:1] == ["-v"]:
        print("2.1.319 (Claude Code)")
        return 0
    if argv[:2] == ["auth", "status"]:
        print(json.dumps({"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
                          "email": "dana@demo.example.com", "orgName": "Demo Engineering",
                          "subscriptionType": "max"}))
        return 0
    if argv[:1] == ["auth"]:
        print("The demo's stand-in for Claude Code signs nobody in or out.", file=sys.stderr)
        return 1
    prompt = sys.stdin.read()
    out = projects.perform(os.getcwd(), prompt, os.environ.get("CLOOP_TASK_ATTACHMENTS", ""))
    sys.stdout.write(out.rstrip() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
