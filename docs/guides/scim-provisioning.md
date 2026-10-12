# SCIM provisioning: deactivation without an administrator

Disabling a person at your identity provider does not, by itself, end anything
the hub has already issued them. Their dashboard session runs until cloop next
re-asks the provider. Their API tokens, glasses links and sandbox leases live
until they expire, and their running tasks keep running. The
[runbook's "Somebody leaves"](../operations/runbook.md#somebody-leaves) lists
all of it, and `cloop hub user offboard` ends it — once somebody remembers to
run it.

SCIM 2.0 provisioning (RFC 7643/7644) removes that somebody. The identity
provider — Microsoft Entra ID or Okta — keeps a copy of its directory on the
hub at `/scim/v2`. When it deactivates an account, the hub suspends that person
**in one request**, and nobody has to be told.

## What the provider can make the hub do

| At the identity provider | It sends | The hub |
| --- | --- | --- |
| A person is assigned to the application | `POST /Users` | Records a provisioned user. That grants no access: roles come from the role policy, as always |
| They are disabled, deleted, unassigned, or fall out of a scoping filter | `active: false` (a `PATCH` or `PUT`) | **Suspends** them — [below](#a-suspension) |
| They are re-enabled, restored or reassigned | `active: true` | Lifts what the suspension wrote. What it ended stays ended |
| They are deleted for good | `DELETE /Users/{id}` | Runs the full offboarding, `cloop hub user offboard`, honouring a [legal hold](#legal-holds) |
| A group is assigned, renamed, or its members change | `POST`/`PATCH /Groups` | The membership becomes a claim, [`scim_group`](#provisioned-groups-as-a-claim), read at every authorization decision |

### A suspension

One transaction writes all of this, so the person is out of all of it or
nothing changed:

- a **deny binding** on every identifier the person is known by (their email,
  subject, and the `preferred_username` or `oid` the hub matched them on);
- their **sessions** end — the dashboard's WebSocket closes with
  `credential_ended`, and `cloop` terminal sessions with it;
- their **API tokens** and **glasses links** are revoked;
- every live **grant over their personal secrets** is suspended: a project
  that leases one of their credentials is refused it by name, until they are
  reactivated.

Then, because these cannot join a database transaction, each in turn:

- their **sandbox leases** are revoked on whichever hub member or executor
  holds them;
- their **running tasks** are told to stop.

What a suspension keeps: their **project memberships** and their **stored
credentials** — personal secrets, Claude Code logins. A suspension is what a
provider means by a disabled account, which is often temporary, and the person
coming back should find their projects where they left them. It does not
re-issue anything: a reactivated person signs in again and mints new tokens.

A reactivation removes only what its suspension wrote. A deny binding an
administrator wrote for the same person — before the suspension or during it —
is not the suspension's to lift, and stays.

`scim.user_suspend` is the audit row, with the counts of each surface ended. If
a lease or a task could not be reached, `scim.user_suspend_incomplete` says
which; alert on it.

### Deletion, and accounts kept disabled

A `DELETE` runs the full offboarding — everything above, plus the stored
credentials destroyed, the memberships removed and the projects reported — as
the actor `scim:<credential name>`, with `via: scim`. It is final: the hub
forgets the provisioned user, and recreating them starts from nothing — except
the offboarding's deny bindings, which stay. A rehire who comes back with the
same address or username is refused until an administrator removes them
(`cloop hub role list --identity <email>`, then `cloop hub role delete <id>
--reason "…"`): access after an offboarding is a decision, not a side effect.

Entra sends a `DELETE` 30 days after an account is deleted, and never for an
account that was merely unassigned. So a hub can be told to finish the job
itself:

```yaml
ui:
  oidc:
    scim:
      offboard_after_days: 30
```

Anyone the provider has kept deactivated for 30 days is then offboarded in full
by the hub's leader, within 15 minutes of the deadline, as
`scim.user_offboard_expired`. That too is final: if the provider reactivates the
account afterwards, the hub marks it active and keeps the offboarding's deny
binding until an administrator removes it, the same way — what was destroyed is
not coming back.

## Setting it up

You need single sign-on (`ui.oidc`) first: provisioning keeps the hub's view
of *people who sign in* current, and `/scim/v2` answers 404 on a hub without
it.

**1. Choose what a provisioned user is matched on.** The provider sends a user
record; the hub has to know which signed-in identity it describes.
`ui.oidc.scim.match_claim` names the claim, and the provider attribute must
carry the same value:

| `match_claim` | Provider attribute | ID token claim | Use it for |
| --- | --- | --- | --- |
| `email` (default) | primary (or work) email | `email` | Okta; Entra when every user has a mailbox |
| `preferred_username` | `userName` | `preferred_username` | Entra's default mappings: both are the user principal name |
| `oid` | `externalId` | `oid` | Entra, with `objectId` mapped to `externalId` — immutable, never reused |
| `sub` | `externalId` | `sub` | Okta, which sends its user ID as `externalId` and as `sub` |

A provisioned user whose value two hub identities carry is **ambiguous**, and
the hub refuses to guess: it denies that value alone and grants neither
identity the user's groups (`scim.match_ambiguous`). A user who carries no value
is **unmatchable** — a deactivation of them reaches nobody. Both are counted by
`cloop hub scim status` and `cloop hub doctor`.

**2. Mint the provider's credential**, on the hub or under
**Settings → Provisioning (SCIM)**:

```console
$ cloop hub scim credential create entra
Minted SCIM credential entra (3f9c1a7e5b2d4c60)

  cloop_scim_3f9c1a7e5b2d4c60_…

This is the only time it is shown. Paste it into the identity provider as the secret token,
with the tenant URL https://<this hub>/scim/v2. The hub keeps only an HMAC of it.
```

The name becomes the audit actor of everything the provider does, `scim:entra`.

**3. Point the provider at `<external_url>/scim/v2`** with that credential as a
bearer token — [Entra](#microsoft-entra-id) or [Okta](#okta) below.

**4. Check it.** After the provider's first cycle:

```console
$ cloop hub scim status
$ cloop hub doctor
```

### Microsoft Entra ID

The [Terraform module](../../deploy/terraform/azure-entra-id/README.md#provisioning-scim)
creates all of this with `scim_provisioning = {}`. By hand, in the Entra admin
center:

1. **Enterprise applications → New application → Create your own
   application**, choose *Integrate any other application you don't find in the
   gallery (Non-gallery)*. A separate application from the one users sign in
   with: Entra provisions only applications created this way.
2. **Provisioning → New configuration** (or *Get started*, mode *Automatic*).
   Authentication: bearer token. **Tenant URL** `https://<hub>/scim/v2`,
   **Secret token** the credential. **Test connection** — the hub answers the
   probe for a random user with an empty list — then save.
3. **Users and groups**: assign the people and groups who can sign in to the
   hub. The scope stays *Sync only assigned users and groups*; with *all users*,
   Entra copies the whole tenant into the hub.
4. **Attribute mapping**, only for `match_claim: oid`: under *Provision
   Microsoft Entra ID Users*, change the source of `externalId` from
   `mailNickname` to `objectId`. Until then the hub counts every user
   unmatchable.
5. **Properties**: a notification email for quarantine, and accidental
   deletions prevention — it pauses the job when one cycle would deactivate more
   users than a threshold, which is what unassigning the wrong group looks like.
6. **Start provisioning.** **Provision on demand** pushes one user now, which
   is how to test a deactivation without waiting for a cycle.

Entra runs a cycle about **every 40 minutes**. A disablement reaches the hub at
the next one; for the next five minutes, offboard by hand.

Entra's dialect is handled as it is spoken: capitalised operations
(`"op": "Replace"`), booleans as the strings `"True"` and `"False"`, member
removal by a list of values, the `ADSCIM` group schema, a manager given as a
bare ID, and the validator's filtered `add` that creates the element it names.
`pkg/ui/testdata/scim` holds recorded Entra provisioning and SCIM Validator
conversations, replayed against a real hub by
`TestSCIM_ReplaysRecordedProvisioningSequences`.

### Okta

1. On the hub's app integration, **General → App Settings → Provisioning:
   SCIM**, save.
2. **Provisioning → Integration**: SCIM connector base URL
   `https://<hub>/scim/v2`, unique identifier field `userName`, provisioning
   actions *Push New Users*, *Push Profile Updates* and *Push Groups*,
   authentication mode *HTTP Header* with the credential as the bearer token.
   **Test Connector Configuration**, save.
3. **Provisioning → To App**: enable *Create Users*, *Update User Attributes*
   and *Deactivate Users*.
4. Set `match_claim: sub`: Okta sends its user ID as `externalId`, and the same
   ID is the `sub` of its tokens.

Okta deactivates with a path-less `PATCH` or, on older integrations, a full
`PUT` with `active: false`; it sends a password, which the hub discards and
never returns; and it renames a group with a value that repeats the group's own
ID. All of that is in the recorded Okta sequence too.

## Provisioned groups as a claim

Groups the provider pushes become a claim kind role bindings can name,
`scim_group`, matched against the group's display name or its `externalId`
(Entra sends the group's object ID there):

```yaml
ui:
  oidc:
    role_mappings:
      - {claim: scim_group, value: "Platform Engineering", role: admin}
      - {claim: scim_group, value: "Payments", role: maintainer, project: payments}
```

or at runtime, `cloop hub role grant scim_group Payments --role maintainer
--project payments --reason "…"`.

The hub reads membership from its copy of the directory **at every
authorization decision**, not from the token: removing someone from the group
at the provider demotes them on their next request after the provider's cycle,
and a group claim has no 200-group overage. Only an active, uniquely matched
provisioned user has groups. A deny binding can name a group too
(`cloop hub role revoke scim_group Contractors --reason "…"`).

## Legal holds

A hold is a standing record that an identity's stored credentials must be kept:

```console
$ cloop hub user hold place alice@example.com --reason "litigation LH-17"
$ cloop hub user hold list
$ cloop hub user hold release alice@example.com --reason "LH-17 closed"
```

Every offboarding of a held identity — a `DELETE` from the provider,
`offboard_after_days`, or an operator's `cloop hub user offboard` — then
behaves as `--keep-credentials` does: access is severed, personal secrets and
Claude Code homes are kept, and `user.offboard_hold` records that the hold was
in force. Releasing the hold destroys nothing by itself; run the offboarding
again to finish it. Holds are keyed by email, or by `sub:<subject>`; give the
one the provider's user carries. Settings → Provisioning lists and edits them
too.

## The credential

- **Minted on the hub, shown once, stored as an HMAC.** Settings →
  Provisioning, `cloop hub scim credential create`, or
  `POST /api/scim/credentials`. Managing credentials needs `user.manage`.
- **Accepted on `/scim/v2` only** — not as an API token, not on the dashboard
  — and only in the `Authorization` header. A wrong one counts towards the
  address's sign-in lockout like any failed credential.
- **Rate-limited per credential**: `ui.oidc.scim.rate_limit_per_minute`
  (default 600, bursts of a sixth). Past it, `429` with `Retry-After`, which
  Entra and Okta both pace on.
- **Rotated with an overlap**: `cloop hub scim credential rotate entra --grace
  1h` prints a new secret and keeps the old one working for the hour — paste the
  new one into the provider inside it. At most seven days.
- **Revoked at once**: `cloop hub scim credential revoke entra --reason "…"`.
  The provider's
  next request is refused with 401, and its job goes into quarantine — which is
  the point if the credential leaked.

Refused requests are audited, a bounded number a minute, as
`scim.request_refused` with the reason: no credential, an unknown or revoked
one, rate limited. Every accepted change is audited under `scim:<name>`; the
[audit reference](../reference/audit-events.md#scim) lists each action.

## Retries, reordering and conflicts

The provider retries, and its requests can arrive out of order. The hub is
built for it:

- **A repeated request changes nothing.** A second deactivation of a suspended
  user writes no second suspension; a member added twice is a member once; a
  removal of an absent member succeeds.
- **Every resource carries a version** (`meta.version`, the `ETag` header). A
  request with `If-Match` that names an older version is refused with 412;
  one without is applied to the current state, retried on a concurrent write.
- **A `PUT` that leaves out `active` leaves it as it is.** A provider
  replaying an old profile update cannot reactivate a suspended user.
- **Unique attributes are enforced** — `userName`, and whatever the match claim
  reads — with 409 `uniqueness`, before anything is suspended.

## What the hub does not support

`/scim/v2/ServiceProviderConfig` advertises bulk operations, sorting and
password changes as unsupported. A request to `/Bulk` or `/Me` is answered with
a SCIM error, a `sortBy` is ignored — results come in creation order — and a
password a provider sends anyway is discarded and never returned.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Every request answers 404 | The hub has no `ui.oidc` — SCIM is served only with single sign-on — or the provider's URL is not `<external_url>/scim/v2` |
| 401, and the provider quarantines the job | Credential unknown, revoked, or rotated and past its grace. `cloop hub scim credential list`, then rotate and paste |
| 429 during the first cycle | The rate limit. Raise `ui.oidc.scim.rate_limit_per_minute` for a large directory; the provider will pace itself either way |
| 409 `uniqueness` for a user | Another provisioned user already has that `userName` or match value — usually an account recreated at the provider while the old one is still provisioned |
| A deactivated person keeps working | Not matched. `cloop hub scim status` counts unmatchable and ambiguous users; with `oid`, check the `externalId` mapping |
| A group binding grants nothing | The user is inactive, ambiguous or unmatched, or the group was not assigned to the provisioning application, so the provider never pushed it |

## See also

- [Configuration reference](../reference/configuration.md) — `ui.oidc.scim`
- [Commands](../reference/commands.md) — `cloop hub scim`, `cloop hub user hold`
- [HTTP API](../reference/http-api.md) — the `/scim/v2` routes and `/api/scim`
- [Threat model](../security/threat-model.md) — what the credential can and cannot do
- [Runbook: somebody leaves](../operations/runbook.md#somebody-leaves)
