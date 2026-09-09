# Getting started

Five pages, in order. They assume nothing except a terminal and a provider you
can reach.

- **[Installation](installation.md)** — prerequisites, `go install`, building
  from source, the container image, and shell completion. Ends with a working
  binary.
- **[Your first project](first-project.md)** — one walkthrough: set a goal,
  read the plan cloop derives from it, run it, watch it, steer it, interrupt it.
  Start here if you only read one page.
- **[How cloop works](concepts.md)** — the loop itself. What a task is, how one
  is picked and how its completion is detected, what happens when one fails,
  and what auto-evolve does once the plan drains.
- **[Choosing and configuring a provider](providers.md)** — the backends, what
  each is good for, how provider and model are actually resolved, and the
  environment variables that override them.
- **[The web dashboard](web-ui.md)** — running `cloop ui`, what each screen
  shows, and the authentication default you should know before binding it to
  anything but localhost.

## After that

Nothing above assumes more than one machine or more than one person. The rest
of the documentation is about relaxing those two assumptions:

- Running work somewhere other than the machine you typed on —
  [executor architecture](../architecture/executors.md).
- Letting other people in — [security model](../security/model.md), then the
  [operator runbook](../operations/runbook.md).
- Giving a task a credential without giving it the credential's full power —
  [secrets and egress](../guides/secrets.md).

---

↩ [documentation map](../README.md)
