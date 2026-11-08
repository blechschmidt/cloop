# Getting started

Seven pages, best read in order. All you need is a terminal and access to a
model provider, and for the last page, a hub that someone runs for your team.

- **[Installation](installation.md)**: what you need, `go install`, building
  from source, the container image and shell completion. At the end you have a
  working `cloop` binary.
- **[Your first project](first-project.md)**: a complete first run. You set a
  goal, read the plan cloop makes from it, run it, watch it, change it and
  stop it. If you only read one page, read this one.
- **[How cloop works](concepts.md)**: what a task is, how cloop picks the next
  one and knows when it is finished, what happens when a task fails, and what
  auto-evolve does once the plan is done.
- **[Choosing and configuring a provider](providers.md)**: the model backends
  cloop can use, what each is good for, how cloop decides which provider and
  model to use, and the environment variables that override that.
- **[The web dashboard](web-ui.md)**: running `cloop ui`, what each screen
  shows, and what to set up before you let anyone else reach it.
- **[A walkthrough of the dashboard](walkthrough.md)**: a first project again,
  this time in the browser, with screenshots. You choose where work may run,
  create a project that runs there, add tasks and start it.
- **[Working from a terminal](terminal.md)**: signing your terminal in to a hub
  with `cloop login`. The terminal prints a code, you approve it in the browser
  you are signed in with, and the terminal gets its own session. Then
  `cloop remote` for projects, tasks, runs and live logs, `cloop task attach`,
  and signing out.

## After that

The pages above assume one machine and one person. The rest of the
documentation covers what changes when there are more:

- To run work on other machines, read the
  [executor architecture](../architecture/executors.md).
- To let other people use cloop, read the
  [security model](../security/model.md), then the
  [operator runbook](../operations/runbook.md).
- To give a task access to a repository, a cluster or the Internet without
  handing over a full credential, read
  [secrets and egress](../guides/secrets.md).

---

↩ [documentation map](../README.md)
