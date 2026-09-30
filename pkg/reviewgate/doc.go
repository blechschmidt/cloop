// Package reviewgate is the review gate (Task 20357): an optional reviewer
// model, configured per project and free to differ from the model that does
// the work, that checks each task's changes before cloop lets them leave the
// working copy.
//
// # What "before" means here
//
// A task's work leaves the machine in three ways, and the gate stands in
// front of each:
//
//   - a merge cloop performs itself — git mode merging a task branch, the
//     parallel merge queue landing a worktree branch — which the orchestrator
//     simply does not perform until the review approves, and then only if the
//     tree it is about to merge is the tree that was reviewed;
//   - a push the agent performs during its turn, which is the common case: a
//     project's constraints say "commit and push after each task", and a
//     granted repository is only worth anything once pushed. Those pushes are
//     held (hold.go) and replayed by cloop after the approval (publish.go);
//   - nothing at all, for a project that only works locally. The review still
//     runs, and in fix mode still sends the agent back, but there is nothing
//     to hold.
//
// # Holding a push without touching the repository
//
// The agent's environment gets `url.cloopgate::.pushInsteadOf` through git's
// GIT_CONFIG_COUNT protocol, which rewrites every push URL to
// `cloopgate::<url>`. git then runs `git-remote-cloopgate`, a two-line script
// on the agent's PATH that execs `cloop review-gate-remote-helper`. The helper
// speaks git's remote-helper protocol just far enough to be handed the
// refspecs, records them, and refuses each with "held by cloop's review gate".
// Nothing is written into the repository — no hook, no config — so a user's
// own hooks keep running, and the rewrite ends with the agent's process.
// Fetches are untouched: pushInsteadOf applies to pushes only.
//
// This is a guardrail against an agent following its instructions to push,
// not a boundary against one that wants to evade it: an agent can unset the
// variables or talk to the forge's API directly. The boundary for isolated
// executors remains the git proxy, which enforces branch restrictions outside
// the sandbox.
//
// # The invariant publishing keeps
//
// cloop never pushes a commit the reviewer did not see. A held push is
// replayed only if every commit it would send — its commits not yet on the
// remote, by the remote-tracking refs — lies in the range the review covered,
// and it is replayed at the reviewed commit rather than at whatever the branch
// points to by then. The review range is chosen to make that hold in the
// ordinary case: when a push was held, the diff starts where the remote's copy
// of the branch forks from HEAD, so earlier unpublished commits are reviewed
// with the task's own rather than slipping out behind them.
package reviewgate
