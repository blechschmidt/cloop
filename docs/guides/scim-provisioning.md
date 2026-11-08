# SCIM provisioning: deactivation without an administrator

Disabling a person at your identity provider doesn't end what the hub has
already issued them. Their dashboard session lasts until cloop next checks
with the provider. Their API tokens, glasses links and sandbox leases last
until they expire, and their running tasks keep running. The
[runbook's "Somebody leaves"](../operations/runbook.md#somebody-leaves) lists
all of it, and `cloop hub user offboard` ends it, but only once someone
remembers to run it.

With SCIM 2.0 provisioning (RFC 7643/7644), the identity provider (Microsoft
Entra ID or Okta) keeps a copy of its directory on the hub at `/scim/v2`. When
it deactivates an account, the hub suspends that person in one request, and
nobody has to do anything.

## What the provider can make the hub do

| At the identity provider | It sends | The hub |
| --- | --- | --- |
| A person is assigned to the application | `POST /Users` | Records a provisioned user. This grants no access: roles still come from the role policy |
| They are disabled, deleted, unassigned, or fall out of a scoping filter | `active: false` (a `PATCH` or `PUT`) | **Suspends** them ([below](#a-suspension)) |
| They are re-enabled, restored or reassigned | `active: true` | Lifts what the suspension wrote. Anything it ended stays ended |
| They are permanently deleted | `DELETE /Users/{id}` | Runs the full offboarding, `cloop hub user offboard`, honouring a [legal hold](#legal-holds) |
| A group is assigned, renamed, or its members change | `POST`/`PATCH /Groups` | The membership becomes a claim, [`scim_group`](#provisioned-groups-as-a-claim), read at every authorization decision |

### A suspension

One transaction writes all of this, so either all of it applies or none of it
does:

- a **deny binding** on every identifier the person is known by (their email,
  subject, and the `preferred_username` or `oid` the hub matched them on);
- their **sessions** end: the dashboard's WebSocket closes with
  `credential_ended`, and so do their `cloop` terminal sessions;
- their **API tokens** and **glasses links** are revoked;
- every live **grant over their personal secrets** is suspended. A project that
  leases one of their credentials is refused it, with an error naming the
  credential, until they are reactivated.

Then, because these cannot join a database transaction, each in turn:

- their **sandbox leases** are revoked on whichever hub member or executor
  holds them;
- their **running tasks** are told to stop.

A suspension keeps their **project memberships** and **stored credentials**
(personal secrets, Claude Code logins), because a disabled account is often
temporary and a returning person should find their projects as they left them.
Nothing is reissued: a reactivated person signs in again and creates new
tokens.

A reactivation removes only what its suspension wrote. A deny binding that an
administrator added for the same person, before or during the suspension,
stays.

The audit row is `scim.user_suspend`, with a count for each kind of access
ended. If a lease or task could not be reached, `scim.user_suspend_incomplete`
says which. Alert on it.

### Deletion, and accounts kept disabled

A `DELETE` runs the full offboarding as the actor `scim:<credential name>`,
with `via: scim`: everything above, plus destroying the stored credentials,
removing the memberships and reporting the projects. It is final. The hub
forgets the provisioned user, and recreating them starts from nothing, except
that the offboarding's deny bindings stay. A rehire with the same address or
username is refused until an administrator removes those bindings
(`cloop hub role list --identity <email>`, then
`cloop hub role delete <id> --reason "…"`).

Entra sends a `DELETE` 30 days after an account is deleted, and never for an
account that was only unassigned. You can have the hub finish the job itself:

```yaml
ui:
  oidc:
    scim:
      offboard_after_days: 30
```

The hub's leader then fully offboards anyone the provider has kept deactivated
for 30 days, within 15 minutes of the deadline, as
`scim.user_offboard_expired`. That is final too: if the provider reactivates
the account afterwards, the hub marks it active but keeps the offboarding's
deny binding until an administrator removes it the same way, and what was
destroyed stays destroyed.

## Setting it up

You need single sign-on (`ui.oidc`) first. Provisioning keeps the hub's view of
people who sign in up to date, and `/scim/v2` answers 404 on a hub without it.

**1. Choose what a provisioned user is matched on.** The provider sends a user
record, and the hub has to know which signed-in identity it describes.
`ui.oidc.scim.match_claim` names the claim, and the provider attribute must
carry the same value:

| `match_claim` | Provider attribute | ID token claim | Use it for |
| --- | --- | --- | --- |
| `email` (default) | primary (or work) email | `email` | Okta; Entra when every user has a mailbox |
| `preferred_username` | `userName` | `preferred_username` | Entra's default mappings: both are the user principal name |
| `oid` | `externalId` | `oid` | Entra, with `objectId` mapped to `externalId`. Immutable, never reused |
| `sub` | `externalId` | `sub` | Okta, which sends its user ID as `externalId` and as `sub` |

A provisioned user whose value two hub identities carry is **ambiguous**. The
hub doesn't guess: it denies that value only and gives neither identity the
user's groups (`scim.match_ambiguous`). A user who carries no value is
**unmatchable**, and deactivating them reaches nobody. `cloop hub scim status`
and `cloop hub doctor` count both.

**2. Create the provider's credential**, on the hub or under
**Settings → Provisioning (SCIM)**:

```console
$ cloop hub scim credential create entra
Minted SCIM credential entra (3f9c1a7e5b2d4c60)

  cloop_scim_3f9c1a7e5b2d4c60_…

This is the only time it is shown. Paste it into the identity provider as the secret token,
with the tenant URL https://<this hub>/scim/v2. The hub keeps only an HMAC of it.
```

The name becomes the audit actor for everything the provider does,
`scim:entra`.

**3. Point the provider at `<external_url>/scim/v2`** with that credential as a
bearer token ([Entra](#microsoft-entra-id) or [Okta](#okta) below).

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
   gallery (Non-gallery)*. It must be separate from the application users sign
   in with, because Entra provisions only applications created this way.
2. **Provisioning → New configuration** (or *Get started*, mode *Automatic*).
   Authentication: bearer token. **Tenant URL** `https://<hub>/scim/v2`,
   **Secret token** the credential. **Test connection** (the hub answers the
   probe for a random user with an empty list), then save.
3. **Users and groups**: assign the people and groups who can sign in to the
   hub. Keep the scope at *Sync only assigned users and groups*. With *all
   users*, Entra copies the whole tenant into the hub.
4. **Attribute mapping**, only for `match_claim: oid`: under *Provision
   Microsoft Entra ID Users*, change the source of `externalId` from
   `mailNickname` to `objectId`. Until then the hub counts every user
   unmatchable.
5. **Properties**: a notification email for quarantine, and accidental
   deletions prevention, which pauses the job when one cycle would deactivate
   more users than a threshold, as unassigning the wrong group would.
6. **Start provisioning.** **Provision on demand** pushes one user now, so you
   can test a deactivation without waiting for a cycle.

Entra runs a cycle about every 40 minutes, and a disabled account reaches the
hub at the next one. To cut someone off within five minutes, offboard them by
hand.

The hub handles Entra's dialect: capitalised operations (`"op": "Replace"`),
booleans as the strings `"True"` and `"False"`, member removal by a list of
values, the `ADSCIM` group schema, a manager given as a bare ID, and the
validator's filtered `add` that creates the element it names.
`pkg/ui/testdata/scim` holds recorded Entra provisioning and SCIM Validator
conversations, which `TestSCIM_ReplaysRecordedProvisioningSequences` replays
against a real hub.

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
`PUT` with `active: false`. It sends a password, which the hub discards and
never returns, and it renames a group with a value that repeats the group's own
ID. The recorded Okta sequence covers all of this too.

## Provisioned groups as a claim

Groups the provider pushes become a claim kind, `scim_group`, that role
bindings can name. It matches the group's display name or its `externalId`
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

The hub reads membership from its copy of the directory at every authorization
decision, not from the token. Removing someone from the group at the provider
demotes them on their next request after the provider's cycle, and there is no
200-group overage. Only an active, uniquely matched provisioned user has
groups. A deny binding can name a group too
(`cloop hub role revoke scim_group Contractors --reason "…"`).

## Legal holds

A hold records that an identity's stored credentials must be kept:

```console
$ cloop hub user hold place alice@example.com --reason "litigation LH-17"
$ cloop hub user hold list
$ cloop hub user hold release alice@example.com --reason "LH-17 closed"
```

Every offboarding of a held identity (a `DELETE` from the provider,
`offboard_after_days`, or an operator's `cloop hub user offboard`) then
behaves like `--keep-credentials`: access is cut off, personal secrets and
Claude Code homes are kept, and `user.offboard_hold` records that the hold was
in force. Releasing the hold destroys nothing by itself. Run the offboarding
again to finish it. Holds are keyed by email or by `sub:<subject>`, so give the
one the provider's user carries. **Settings → Provisioning** lists and edits
them too.

## The credential

- **Created on the hub, shown once, stored as an HMAC.** Through
  **Settings → Provisioning**, `cloop hub scim credential create`, or
  `POST /api/scim/credentials`. Managing credentials needs `user.manage`.
- **Accepted on `/scim/v2` only**, not as an API token or on the dashboard, and
  only in the `Authorization` header. It is checked before anything else, so a
  correct credential is accepted even from a locked-out address. A wrong one
  counts against SCIM's own lockout (five a minute per address, then `429` for
  a minute), kept apart from the dashboard's sign-in lockout so that neither a
  neighbour on the provider's egress address nor a misconfigured client beside
  the dashboard can lock out the other.
- **Rate-limited per credential**: `ui.oidc.scim.rate_limit_per_minute`
  (default 600, in bursts of up to a sixth). Past it, the hub answers `429`
  with `Retry-After`, which Entra and Okta both honour.
- **Rotated with an overlap**:
  `cloop hub scim credential rotate entra --grace 1h` prints a new secret and
  keeps the old one working for the hour, so paste the new one into the
  provider within it. The grace is at most seven days.
- **Revoked at once**: `cloop hub scim credential revoke entra --reason "…"`.
  The provider's next request is refused with 401 and its job goes into
  quarantine, which is what you want if the credential leaked.

Refused requests are audited, with a per-minute cap, as `scim.request_refused`
with the reason: no credential, an unknown or revoked one, or rate limited.
Every accepted change is audited under `scim:<name>`, and the
[audit reference](../reference/audit-events.md#scim) lists each action.

## Retries, reordering and conflicts

Providers retry, and their requests can arrive out of order. The hub handles
both:

- **A repeated request changes nothing.** A second deactivation of a suspended
  user writes no second suspension, a member added twice is a member once, and
  removing an absent member succeeds.
- **Every resource carries a version** (`meta.version`, the `ETag` header). A
  request whose `If-Match` names an older version is refused with 412. One
  without `If-Match` is applied to the current state, and retried on a
  concurrent write.
- **A `PUT` that leaves out `active` leaves it as it is.** A provider
  replaying an old profile update cannot reactivate a suspended user.
- **Unique attributes are enforced** (`userName` and whatever the match claim
  reads) with 409 `uniqueness`, before anything is suspended.

## What the hub does not support

`/scim/v2/ServiceProviderConfig` advertises bulk operations, sorting and
password changes as unsupported. A request to `/Bulk` or `/Me` gets a SCIM
error, `sortBy` is ignored (results come in creation order), and a password a
provider sends anyway is discarded and never returned.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Every request answers 404 | The hub has no `ui.oidc` (SCIM is served only with single sign-on), or the provider's URL is not `<external_url>/scim/v2` |
| 401, and the provider quarantines the job | Credential unknown, revoked, or rotated and past its grace period. Check `cloop hub scim credential list`, then rotate and paste |
| 429 during the first cycle | The rate limit. Raise `ui.oidc.scim.rate_limit_per_minute` for a large directory. The provider paces itself either way |
| 409 `uniqueness` for a user | Another provisioned user already has that `userName` or match value, usually an account recreated at the provider while the old one is still provisioned |
| A deactivated person keeps working | Not matched. `cloop hub scim status` counts unmatchable and ambiguous users. With `oid`, check the `externalId` mapping |
| A group binding grants nothing | The user is inactive, ambiguous or unmatched, or the group was not assigned to the provisioning application, so the provider never pushed it |

## See also

- [Configuration reference](../reference/configuration.md): `ui.oidc.scim`
- [Commands](../reference/commands.md): `cloop hub scim`, `cloop hub user hold`
- [HTTP API](../reference/http-api.md): the `/scim/v2` routes and `/api/scim`
- [Threat model](../security/threat-model.md): what the credential can and cannot do
- [Runbook: somebody leaves](../operations/runbook.md#somebody-leaves)
