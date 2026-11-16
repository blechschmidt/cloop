# Letting one project read another

A run sees its own project's files and nothing else on the hub. Sometimes the
work in one project needs to read another: a web client that has to match the
handlers of an API kept in its own project, or a service built on a shared
library that lives in a project of its own. To allow that, you put the project
that needs to read on the other project's **readers list**. Every run of a
project on that list is then given the other project's files, read-only.

This page shows how to keep a readers list in the dashboard, from a terminal
and over the HTTP API. What a run receives, and how a removal reaches a run
that is already going, is in
[reading another project's tree](../security/model.md#reading-another-projects-tree).

## How a readers list works

- A project's readers list names the other projects whose runs may read it.
  Nothing else lets one project read another: having the same owner, running
  on the same executor or being one of its features gives no access.
- Access goes one way. If `shop` lists `billing`, runs of `billing` can read
  `shop`, and runs of `shop` still can't read `billing` until `billing` lists
  `shop`.
- A run can only read. It gets the files git would commit from the project's
  working tree, without its history and without `.cloop` or `.git`, and it
  can't change them.
- A project is never on its own list. A feature has no list of its own and is
  never on a list: name its project instead. A feature's runs are not given
  anything through their project's entries.

## Who can see and change it

| You are | You see | You can |
| --- | --- | --- |
| an administrator of the project: its owner, a member at `admin` or a hub administrator. On a hub without single sign-on, anyone who can use the dashboard | every entry; one naming a project you can't see shows as **A project you can't see** | add and remove readers |
| anyone else who can open the project | the readers you can see, and how many others there are | nothing |

Everyone who can open the project also sees which projects it can read.
Those entries are on the other projects' lists, so only their administrators
change them.

## In the dashboard

Open the project. On its **Overview**, the **Readers** section comes after
**Members** on a hub with single sign-on, and after **Features** on one
without. It has two lists:

- **Readers**: the projects whose runs get this project's files. Each row says
  who added it and when. The badge next to the heading counts them, including
  any you can't see.
- **Can read**: the projects this project's runs get, with who listed this
  project there and when.

To let another project read this one, pick it from **Choose a project…** and
press **Add reader**. The list holds the projects you can see that aren't
readers already. This project and its features are never offered.

On a hub with single sign-on, a change needs a recent sign-in. If you signed in
more than two hours ago (`ui.oidc.sudo_max_age_minutes`), the dashboard opens
**Confirm it's you**. Sign in again in the window it opens, and the change you
asked for goes through. See
[recent sign-in for privileged actions](../security/model.md#recent-sign-in-for-privileged-actions).

To stop a project reading this one, press **Remove** on its row and confirm.
A run of that project that is already going keeps the files until its current
task ends, and starts its next task without them. Its next knowledge search or
git fetch from this project is refused straight away.

An entry naming a project you can't see shows as **A project you can't see**,
with who added it and when. An administrator can still remove it, and learns
nothing about the other project by doing so.

If you aren't an administrator of the project, the section shows the lists
without any buttons and says who can change them.

Every open dashboard follows changes as they happen, other people's included.
When an entry is added or removed, the hub sends each dashboard showing either
project its lists, drawn for the person looking at it, so nobody is shown a
project they can't see. It does the same for every open Overview whenever who
can see which project changes: a project is shared or stops being shared, a
team's members change, or a project is added to the hub or removed from it.
A project shared with you is then named in the lists, and offered in the
picker, without reloading the page. A dashboard that lost its connection
reads the lists again when it reconnects.

## From a terminal

`cloop project readers` asks the hub, the way the dashboard does:

```bash
cloop project readers ls shop            # who may read shop, and what shop may read
cloop project readers add shop billing   # billing's runs may read shop
cloop project readers rm shop billing
```

See [`cloop project readers`](../reference/commands.md#cloop-project-readers)
for the options and for removing an entry naming a project you can't see.

## Over the HTTP API

The three routes address the project the way every `/api/projects/{idx}/…`
route does: by its index in your own project list, `GET /api/projects`. The
[HTTP API reference](../reference/http-api.md) lists them with their
permissions.

### Reading the lists

`GET /api/projects/{idx}/readers` needs `project.read`.

```json
{
  "project": "shop",
  "path": "/srv/projects/shop",
  "readers": [
    {
      "id": "prd_0f3c2a7d10b4e865a1b2c3d4",
      "project": "billing",
      "path": "/srv/projects/billing",
      "idx": 2,
      "added_by": "alice@example.com",
      "added_at": "2026-11-16T08:12:44Z"
    }
  ],
  "hidden_readers": 1,
  "hidden": [
    {"id": "prd_9a1b5e0c2f7d3a8b6c4e1d09", "added_by": "root@example.com", "added_at": "2026-11-15T17:03:10Z"}
  ],
  "readable": [],
  "hidden_readable": 0,
  "can_manage": true,
  "candidates": [
    {"project": "warehouse", "path": "/srv/projects/warehouse", "idx": 3}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `project`, `path` | the project at `{idx}` |
| `readers` | the projects on its list that you can see. `idx` is the reader's index in your project list, `id` is the entry's |
| `hidden_readers` | how many entries name a project you can't see, or one no longer on the hub |
| `hidden` | those entries' ids, who added them and when. Sent only with `can_manage` |
| `readable` | the projects this one may read that you can see. `id` is the entry on the other project's list |
| `hidden_readable` | how many more it may read that you can't see |
| `can_manage` | whether you may change this project's list (`project.readers`) |
| `candidates` | the projects you could add: the ones you can see that are not this project, not a feature and not on the list already. Sent only with `can_manage` |
| `feature`, `note` | set instead of the lists when the project at `{idx}` is a feature |

An index can point at a different project once the project list changes. When
you add or remove a reader by hand, name it by `path` or by the entry's `id`.

### Adding a reader

`PUT /api/projects/{idx}/readers` needs `project.readers`, and on a hub with
single sign-on a recent sign-in. Name the reader by its path, or by its index
in your project list:

```json
{"reader": "/srv/projects/billing"}
```

```json
{"reader_idx": 2}
```

The answer is the entry. `added` is `false` when the reader was on the list
already, in which case nothing changed and no audit row was written:

```json
{
  "added": true,
  "reader": {
    "id": "prd_0f3c2a7d10b4e865a1b2c3d4",
    "project": "billing",
    "path": "/srv/projects/billing",
    "idx": 2,
    "added_by": "alice@example.com",
    "added_at": "2026-11-16T08:12:44Z"
  }
}
```

### Removing a reader

`DELETE /api/projects/{idx}/readers` takes the entry in the query string,
because some clients and proxies drop a `DELETE` body. It needs the same as
adding one.

```text
DELETE /api/projects/0/readers?reader=/srv/projects/billing
DELETE /api/projects/0/readers?id=prd_9a1b5e0c2f7d3a8b6c4e1d09
```

Use `?id=` for an entry naming a project you can't see. The answer is
`{"ok": true, "id": "prd_…"}`, with `"reader": "<path>"` added when you named
the reader or can see it.

### Errors

| Status | When |
| --- | --- |
| `400` | `{idx}` is not an index in your project list; the request names no reader, or names it twice; a path or entry id that isn't one; the reader is this project, or a feature |
| `401` `REAUTH_REQUIRED` | a change on a hub with single sign-on, from a session that signed in too long ago. Sign in again and repeat it |
| `403` | you lack `project.read` to read the lists, or `project.readers` to change them |
| `404` | the reader is not among the projects you can see, or the list has no such entry |
| `409` | the project at `{idx}` is a feature, which has no list of its own; or your project list changed while the request was handled, so read it again and repeat |

Each change is recorded in the audit trail as
[`project.reader.add`](../reference/audit-events.md#projectreader) or
[`project.reader.remove`](../reference/audit-events.md#projectreader).

### Following changes

A dashboard's WebSocket (`/api/ws`) receives a `project_readers` message, and
its event stream (`/api/events`) a `project_readers` event, whenever an entry
naming the project it was opened for is added or removed, and whenever who can
see which project changes on the hub. The data is what
`GET /api/projects/{idx}/readers` would answer for the credential that opened
the stream at that moment. A stream whose credential has ended, or that may no
longer read the project, is sent nothing. The hub sends these one round at a
time, so the last message a stream gets shows the lists after the last change.
A message can still be lost while a stream reconnects, so a client should read
the lists again when it does.

```json
{"type": "project_readers", "data": {"project": "shop", "path": "/srv/projects/shop", "readers": [], "hidden_readers": 0, "readable": [], "hidden_readable": 0, "can_manage": false}}
```
