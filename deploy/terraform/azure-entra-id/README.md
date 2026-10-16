# cloop SSO on Microsoft Entra ID

A Terraform module that creates the Entra ID (Azure AD) application a cloop hub
signs users in against, and prints the `ui.oidc` block to paste into the hub's
config.

```hcl
module "cloop_sso" {
  source        = "github.com/blechschmidt/cloop//deploy/terraform/azure-entra-id"
  hub_base_urls = ["https://cloop.example.com"]
}
```

```console
$ terraform apply
$ terraform output -raw cloop_config_yaml >> .cloop/config.yaml
$ cloop ui
```

There is no third line exporting a secret, and that is the default: the
registration is a **public client** and the hub authenticates the code exchange
with PKCE. Nothing has to be rotated, distributed to each replica, or revoked
on the day it leaks. Set `client_type = "confidential"` to get a client secret
back — see [Credentials](#credentials).

It is an example in the sense that it is meant to be read and adapted, and a
module in the sense that it works as it stands. What it is not is a generic app
registration: every decision below follows from something cloop does with the
token, and the ones that are not obvious are the reason this exists.

---

## What it creates

| Resource | Why |
| --- | --- |
| `azuread_application` | The registration: public-client platform by default, single-tenant, four app roles, `email` optional claim, four delegated Graph scopes |
| `azuread_service_principal` | The enterprise app. Assignments and Conditional Access attach here, not to the application |
| `azuread_application_password` | The client secret — **only** when `client_type = "confidential"` |
| `time_rotating` | Its rotation schedule, held still between rotations so plans do not churn |
| `azuread_app_role_assignment` | One per (role, group-or-user) pair you declare |
| `azuread_application_from_template` | The provisioning application, **only** with `scim_provisioning` — see [Provisioning](#provisioning-scim) |
| `azuread_synchronization_secret` | Its connection: the hub's `/scim/v2` URL, the hub's SCIM credential, and the scope |
| `azuread_synchronization_job` | The provisioning job itself, created started |
| `azuread_app_role_assignment` (provisioning) | One per principal in the job's scope |

---

## Five things that are not obvious

Each of these is a real failure mode, and each is decided for you by the
defaults. They are written down because the symptom never names the cause.

### 1. Single-tenant, and there is no knob

cloop pins the issuer. `pkg/oidcauth` compares the discovery document's
`issuer` and the ID token's `iss` against the configured string, for equality.
A multi-tenant registration issues tokens whose `iss` names the *signing-in
user's* home tenant, so no single configured value can match them all. The
module sets `sign_in_audience = "AzureADMyOrg"` and offers no way to change it,
because the alternative does not produce a working hub.

For the same reason the issuer is `https://login.microsoftonline.com/<tenant>/v2.0`
and never `.../common/v2.0`.

### 2. The `/v2.0` suffix is load-bearing

The v1.0 endpoint issues tokens whose `iss` is `https://sts.windows.net/<tid>/`.
Configure cloop with a v1.0 issuer and every sign-in fails validation after
appearing to succeed at Microsoft. The `issuer` output always carries `/v2.0`;
if you hand-write it, carry it too.

### 3. Two redirect URIs per hub, and the trailing slash matters

`https://cloop.example.com/auth/callback` is the obvious one — the route
`pkg/ui` serves, asserted against the hub's own route table by
`tests/docs/terraform_azure_test.go`.

`https://cloop.example.com/` is the one people miss. On sign-out cloop sends
Entra a `post_logout_redirect_uri` built as `scheme://host/` — with the
trailing slash — and Entra honours a post-logout URI only if it is registered.
Unregistered, sign-out dead-ends on a generic Microsoft page instead of
returning to the dashboard. The module registers both.

### 4. `offline_access`, or IdP revocation silently stops working

cloop sends exactly the scopes it is configured with, and its default is
`openid profile email`. Entra issues a refresh token only when
`offline_access` is asked for — and without a refresh token, two things go
dark with no error anywhere:

- **`refresh_interval_minutes`**, the background re-check that ends a session
  after the IdP disables the account.
- **`max_claim_age_minutes`**, the synchronous re-check before any action above
  operator — granting a secret, managing a user, writing config.

Sign-in keeps working perfectly. A disabled account simply keeps its session
until one of the two timeouts fires. So the rendered config requests
`offline_access`, the registration requests the matching Graph permission, and
a test fails if either loses it.

Retaining the refresh token also needs `CLOOP_SECRET_KEY` set on the hub —
without it cloop does not store one, and you are back to the same place. See
[the security model](../../../docs/security/model.md).

### 5. App roles, not group claims

cloop can bind roles on a `group` claim, and on Entra that is the worse
instrument:

- Values are group **object IDs** — GUIDs — not names, unless the group is
  synced from on-premises AD.
- The claim is **capped**. Past 200 groups in a JWT, Entra omits `groups`
  entirely and substitutes `_claim_names`/`_claim_sources` pointing at
  Microsoft Graph. cloop does not follow that indirection: it reads no groups
  and falls back to `default_role`. That is a silent demotion, and it lands on
  the longest-tenured people first, because they are in the most groups.

App roles have neither problem. The role value lands in the `roles` claim
verbatim, means "what this person may do *here*", and the four of them are
checked against `pkg/authz`'s ladder by the same test.

`emit_group_claims = true` turns the claim on anyway, defaulting to
`ApplicationGroup` — only groups assigned to this application, which is the one
setting that keeps the claim bounded.

---

## Deny-by-default on both sides

`require_app_role_assignment` (default `true`) tells Entra to refuse a token to
anyone holding no app role. `cloop_default_role` (default `none`) tells cloop
to grant nothing to an identity that matches no mapping.

Together they mean a fresh apply lets **nobody** in, including you. That is
deliberate: the first person through the door should be someone who was
deliberately granted access, not everyone in the directory while somebody works
out the role mappings.

An unassigned user gets **AADSTS50105**, which names the application and is
searchable. The alternative — a successful sign-in onto an empty dashboard —
produces a support ticket that says "cloop is broken".

Assigning an app role to a **group** requires Microsoft Entra ID P1 or above.
On the Free tier, use `user_object_ids`, or set `emit_group_claims = true` and
bind on the group claim in cloop instead.

---

## Credentials

By default there are none, and everything in the rest of this section is
inapplicable. `client_type = "public"` registers the redirect URIs on Entra's
public-client platform ("Mobile and desktop applications" in the portal,
`InstalledClient` in the manifest), and Entra then redeems a code presented
with a `client_id` and a PKCE verifier and no credential at all.

Three things about that are worth stating, because each is commonly assumed the
other way:

- **An ordinary `https://` URI is allowed there.** The `localhost` and
  `nativeclient` values in Microsoft's docs are recommendations, not an
  allowlist; Microsoft's own App Service guide registers an
  `https://…/.auth/login/aad/callback` on that platform.
- **It is not the "Allow public client flows" toggle.** That flag
  (`fallback_public_client_enabled`, `isFallbackPublicClient`) is consulted
  only for flows that carry no redirect URI — ROPC, device code — so it does
  nothing for sign-in while enabling those. The module leaves it `false` under
  both client types.
- **It is not an SPA registration.** Entra refuses to redeem a code for an
  `spa`-typed URI unless the request carries an `Origin` header
  (**AADSTS9002327**), and the hub redeems server-side from Go. SPA
  registrations also get 24-hour refresh tokens.

What you give up: this registration can no longer obtain app-only tokens
(client credentials) or use on-behalf-of. cloop needs neither — it reads the ID
token and nothing else.

Set `client_type = "confidential"` where a policy requires client
authentication. That registers the URIs on the Web platform and mints a secret,
which you then supply out of band:

```console
$ export CLOOP_OIDC_CLIENT_SECRET=$(terraform output -raw client_secret)
```

With `create_client_secret = false` alongside it, no secret is created and you
supply a certificate or a federated identity credential yourself — still a
confidential client, credential obtained elsewhere. Asking for
`create_client_secret = true` on a *public* client is refused at plan time
rather than silently ignored, because Entra will not accept a credential for a
code issued to a public-client URI: the secret could never be presented.

### Rotation

Applies to `client_type = "confidential"` only.

The client secret rotates on a schedule (`client_secret_rotation_days`,
default 180) and expires `client_secret_grace_days` (default 30) later. The
gap is the margin for a pipeline that runs late: with no margin, expiry and
rotation coincide and a missed apply is an outage.

Rotation happens on the next apply *after* the date falls due, so the schedule
is only as real as how often you run Terraform. Put
`client_secret_expires_at` in a calendar. An expired secret fails every new
sign-in with **AADSTS7000222** while existing sessions keep working, so the
outage arrives gradually and looks like something else.

For a suspected leak, bump `client_secret_rotation_token` — that rotates
immediately with no grace window, and the hub must be restarted with the new
value promptly.

The secret is in Terraform state. Use a backend that encrypts it.

---

## Consent

Visit `admin_consent_url` once, as a Privileged Role Administrator, to consent
for the whole tenant. Skip it and each user is prompted individually on first
sign-in — and `offline_access` is the scope users most often decline, which
disables IdP revocation for that user alone. That is a per-user hole nothing
will report.

---

## Conditional Access

The module deliberately creates no policies: they are a tenant-wide concern and
belong with the rest of your CA estate, not in the SSO module for one app.
`service_principal_object_id` is what you scope them to. Requiring MFA for
cloop specifically is a reasonable thing to do with it — the hub can grant
credentials to a sandbox and attach to a running one.

---

## Provisioning (SCIM)

Sign-in alone leaves a gap: a person disabled in Entra keeps a working hub
session until cloop next re-asks Entra, keeps their API tokens until someone
revokes them, and keeps any sandbox lease they hold. Provisioning closes it.
Entra's provisioning service tells the hub about every account in scope, and
when one is disabled, deleted or unassigned it sends `active: false` — on which
the hub suspends the person in one request: a deny binding on their identity,
and their sessions, API tokens, glasses links, sandbox leases and running tasks
ended. Nobody has to notice, and nobody has to run anything.

```hcl
module "cloop_sso" {
  source        = "github.com/blechschmidt/cloop//deploy/terraform/azure-entra-id"
  hub_base_urls = ["https://cloop.example.com"]

  role_assignments  = { operator = { group_object_ids = [data.azuread_group.engineering.object_id] } }
  scim_provisioning = {}
  scim_secret_token = var.cloop_scim_token
}
```

It takes two applies, because the credential comes from the hub:

1. Apply without provisioning, configure the hub from `cloop_config_yaml`, and
   start it.
2. On the hub, `cloop hub scim credential create entra` prints the credential
   once (Settings → Provisioning does the same from the dashboard). Apply again
   with it as `scim_secret_token`, and merge the `scim:` block that now
   appears in `cloop_config_yaml`.

The hub must be reachable from Microsoft's provisioning service, which calls it
over the internet — unlike sign-in, where only users' browsers do.

### Why a second application

Entra runs a provisioning job only on an enterprise application instantiated
from a template; the sign-in registration is a plain app registration, and
re-instantiating it would replace it — client ID, assignments and all. So the
module instantiates Entra's non-gallery template a second time. That
application signs nobody in. It carries the job, the connection, and the
assignments that are the job's scope: the scope is **Sync only assigned users
and groups** (`SyncAll = false`), and by default everyone in
`role_assignments` is assigned — the people who can sign in are the people to
deprovision. `scim_provisioning.group_object_ids` and `user_object_ids` add
more.

### What Entra sends, and what the hub does

| In Entra | Sent | On the hub |
| --- | --- | --- |
| Account assigned (directly or through a group) | `POST /Users` | A provisioned user; no access by itself |
| Sign-in blocked, account deleted, unassigned, or out of a scoping filter | `PATCH active: false` | **Suspended**: deny binding, sessions, API tokens, glasses links, leases and running tasks end; grants over their personal secrets suspend. Memberships and stored credentials are kept |
| Re-enabled, restored or reassigned | `PATCH active: true` | The suspension's deny binding and grant suspensions are lifted. What ended stays ended: they sign in again |
| Hard-deleted — 30 days after deletion, or purged from the recycle bin | `DELETE /Users/{id}` | Full offboarding, as `cloop hub user offboard` — unless a legal hold keeps their credentials |
| Group assigned; members added or removed | `POST /Groups`, `PATCH members` | Membership becomes the `scim_group` claim, read at every authorization decision |

Two consequences worth knowing. Entra sends a `DELETE` only for a user it still
manages, so a user who was **unassigned** stays suspended indefinitely —
`scim_provisioning.offboard_after_days` runs the full offboarding for anyone
kept deactivated that long. And Entra works in **cycles, about every 40
minutes**: a disable reaches the hub at the next one, not the moment it is
made. **Provision on demand** on the provisioning application pushes one user
now; the dashboard's offboarding is still the tool for the next five minutes.

### Matching a provisioned user to a person

The hub has to know which signed-in identity a provisioned user is. The
rendered `ui.oidc.scim.match_claim` says how:

- **`preferred_username`** (the default) — Entra's default mapping provisions
  `userName` from the `userPrincipalName`, which is what the ID token's
  `preferred_username` carries. No portal changes, and guests work: Entra
  strips the `#EXT#` suffix from a guest's UPN before provisioning it.
- **`oid`** — the object ID, which never changes or gets reused. Entra's
  default mapping sends `mailNickname` as `externalId`, though, so this needs
  one step the provider cannot take: on the provisioning application,
  **Provisioning → Attribute mapping → Provision Microsoft Entra ID Users →
  externalId**, change the source attribute to `objectId`, save. Until then the
  hub counts every user as unmatchable, and `cloop hub doctor` says so.
- **`email`** — the `mail` attribute, sent as the work email. Users with no
  mailbox have none, and cannot be matched.

A user two hub identities could be is refused rather than guessed — the hub
denies the claim value alone and grants neither identity the user's groups.

### Binding roles to provisioned groups

Provisioned groups become a claim role mappings can name, without
`emit_group_claims` and without the 200-group overage:

```hcl
cloop_extra_role_mappings = [
  { claim = "scim_group", value = "Payments", role = "maintainer", project = "payments" },
]
```

The value is the group's display name or its object ID (Entra's default group
mapping sends the object ID as `externalId`). Membership is read at every
decision, so removing someone from the group in Entra demotes them at the next
cycle, on their next request. Only assigned groups are provisioned, so assign
the group to the provisioning application (`scim_provisioning.group_object_ids`)
as well.

### What the provider cannot set

Set these on the provisioning application in the portal if you want them;
Terraform leaves them alone:

- **Notification email** (Provisioning → Overview → Properties): an address to
  hear from when the job goes into quarantine — which is how a revoked or
  expired hub credential shows up.
- **Accidental deletions prevention** (same place): pauses the job when one
  cycle would deactivate more than a threshold of users, which is what
  unassigning the wrong group looks like.
- **Visible to users** (Properties): the provisioning application has no
  sign-in of its own, so its tile in My Apps leads nowhere; set it to No.

The module's synchronization secret holds the endpoint, the credential and the
scope. Entra stores those as one set and the provider writes them as one, so
change the scope here, not in the portal.

### Rotating the credential

```console
$ cloop hub scim credential rotate entra --grace 1h    # on the hub
$ TF_VAR_cloop_scim_token=cloop_scim_… terraform apply  # within the hour
```

The old credential keeps working for the grace period, so a cycle in flight
does not fail. The credential is in Terraform state — Entra never returns it —
so the state backend must encrypt. `cloop hub scim credential revoke entra
--reason "…"` stops provisioning at once; the next cycle fails with 401 and the job goes into
quarantine.

---

## Key Vault for the sealing keys (`modules/key-vault-kms`)

A hub can hold the key-encryption keys of its secret store in Key Vault instead
of deriving them from `CLOOP_SECRET_KEY` (`secrets.kms`, Task 20433): each key is
random, the hub's database keeps only the ciphertext Key Vault's `wrapKey` made of
it, and a copy of the database and of the key file opens nothing without the
vault. The hub reaches the vault through the AKS KMS plugin — the Kubernetes KMS
v2 plugin the API server's own encryption at rest uses — run as a sidecar by the
Helm chart.

[`modules/key-vault-kms`](modules/key-vault-kms) creates what that needs, in a vault
you already run:

* **The key** — RSA 3072, HSM-protected by default (`hsm = false` for a Standard
  vault), whose operations are `wrapKey` and `unwrapKey` and nothing else, with an
  optional rotation policy (`rotate_after_days`).
* **The hub identity's permission** — *Key Vault Crypto Service Encryption User*
  (read the key's metadata, wrap, unwrap) for `principal_object_id`, scoped to
  that one key; or, on a vault that still uses access policies
  (`authorization = "access_policy"`), get, wrapKey and unwrapKey on its keys.
  Never decrypt, never secrets. Removing it is how the hub's access is revoked.

```hcl
module "cloop_kms" {
  source = "github.com/blechschmidt/cloop//deploy/terraform/azure-entra-id/modules/key-vault-kms"

  key_vault_id        = azurerm_key_vault.platform.id
  principal_object_id = azurerm_user_assigned_identity.cloop_hub.principal_id
}

output "cloop_kms_helm_values" {
  value = module.cloop_kms.helm_values_yaml
}
```

It is a module of its own because Key Vault is an Azure Resource Manager resource:
it needs the `azurerm` provider, and putting it in this module would make every
caller configure `azurerm` — subscription and all — whether it wants a KMS or not.
See [examples/complete](examples/complete) for both together.

Outputs: `helm_values_yaml` (the chart's `kms` block — pin the plugin image, and
create the `kms-azure-json` Secret holding the plugin's `azure.json`),
`cloop_secrets_yaml` (the `secrets` section for a hub installed without the
chart), `kms_plugin_args`, `key_id`, `key_version`, `key_name`, `key_vault_name`
and `key_resource_id`.

Two things are the vault's, not the module's, and both matter: **soft delete and
purge protection**, because a purged key takes every secret the hub sealed with
it and no restore of the database brings them back; and **keeping old key
versions** until `cloop hub key list` names them on no live key — the hub
rewraps onto a new version as soon as the plugin is pointed at it, but a backup
from before that still needs the old one. Moving a running hub onto the key is
in the [runbook](../../../docs/operations/runbook.md#keys-in-a-kms).

## Inputs

| Name | Type | Default | |
| --- | --- | --- | --- |
| `hub_base_urls` | `list(string)` | — | **Required.** External hub URLs, no trailing slash |
| `display_name` | `string` | `"cloop hub"` | Shown in the portal and on the consent screen |
| `description` | `string` | … | Stored on the application object |
| `owners` | `list(string)` | `[]` | Directory principals who may administer the app |
| `tags` | `list(string)` | `["cloop", "terraform-managed"]` | Entra tags are plain strings |
| `extra_redirect_uris` | `list(string)` | `[]` | e.g. a developer's `http://localhost:8080/auth/callback` |
| `client_type` | `string` | `"public"` | `"public"` = PKCE only, no secret. `"confidential"` = Web platform with a credential |
| `create_client_secret` | `bool` | `null` | Follows `client_type`. `false` on a confidential client supplying a certificate or federated credential |
| `client_secret_rotation_days` | `number` | `180` | Confidential only |
| `client_secret_grace_days` | `number` | `30` | Margin for a late apply |
| `client_secret_rotation_token` | `string` | `"initial"` | Change to rotate now |
| `require_app_role_assignment` | `bool` | `true` | Entra refuses unassigned users |
| `role_assignments` | `map(object)` | `{}` | cloop role → group/user object IDs |
| `allow_service_principal_roles` | `bool` | `false` | Let machine identities hold roles |
| `emit_group_claims` | `bool` | `false` | See §5 |
| `group_membership_claims` | `list(string)` | `["ApplicationGroup"]` | |
| `cloop_default_role` | `string` | `"none"` | |
| `cloop_admin_emails` | `list(string)` | `[]` | Break-glass; prefer the `admin` app role |
| `cloop_extra_role_mappings` | `list(object)` | `[]` | Project- and executor-scoped grants |
| `scim_provisioning` | `object` | `null` | Turns on [provisioning](#provisioning-scim); `{}` takes every default |
| `scim_secret_token` | `string` (sensitive) | `null` | The credential `cloop hub scim credential create` printed |

## Outputs

`cloop_config_yaml` is the one you want. The rest —`client_id`, `client_type`,
`client_secret`, `client_secret_expires_at`, `issuer`, `discovery_url`,
`redirect_url`, `redirect_uris`, `tenant_id`, `application_object_id`,
`service_principal_object_id`, `app_role_ids`, `admin_consent_url`,
`app_role_assignment_required` — are either fields of it or things you need
when a sign-in does not work. With provisioning, `scim_base_address`,
`provisioning_service_principal_object_id`, `provisioning_job_id` and
`provisioning_app_role_id` say where Entra provisions and what it was given.
`terraform output` describes each.

---

## Testing

The module has a suite that needs no Azure tenant:

```console
$ terraform init -backend=false
$ terraform test
Success! 26 passed, 0 failed.
```

It mocks the provider, so it proves nothing about what Entra accepts — only an
apply against a real tenant does that. What it does prove is everything
decidable from the configuration: both redirect URIs and *which platform block
carries them*, the `/v2.0` issuer, the rendered scopes, the derived app role
IDs, and that the input validation refuses the URLs Entra would refuse later
and less clearly.

The platform assertions are the ones to keep if you trim: public-vs-confidential
is decided entirely by whether the URIs sit in `public_client` or `web`, and
the computed `redirect_uris` output is identical either way — so nothing else
in the suite can tell the two registrations apart.

The joins to cloop itself are checked from Go, in
[`tests/docs/terraform_azure_test.go`](../../../tests/docs/terraform_azure_test.go),
where both sides are visible: that the callback path is a route `pkg/ui` still
serves, that the four app roles are `pkg/authz`'s ladder, that the rendered
YAML keys are fields of `config.OIDCConfig`, that the environment variable is
the one `pkg/config` reads, that every scope the config requests is a
permission the registration was granted — and, for provisioning, that the
SCIM path is where the hub serves SCIM, that the credential pattern accepts
exactly what the hub's parser does, and that every match claim is one the hub
starts with.

`make terraform-test` runs both, and CI runs that.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| **AADSTS50011** redirect URI mismatch | `ui.oidc.redirect_url` differs from what is registered — usually a hub reached on a different hostname than `hub_base_urls` |
| **AADSTS50105** user not assigned | Working as intended. Assign an app role, or set `require_app_role_assignment = false` |
| **AADSTS7000218** request body must contain `client_assertion` or `client_secret` | The two sides disagree about the client type: the callback is registered on the Web platform but the hub has no secret. Either `client_type = "public"` here, or export `CLOOP_OIDC_CLIENT_SECRET` there |
| **AADSTS7000222** invalid client secret | Expired. Apply to rotate, then restart the hub |
| **AADSTS9002327** tokens for the SPA client-type may only be redeemed cross-origin | A redirect URI got registered on the SPA platform. cloop now recovers from this by retrying the exchange with an `Origin` header, so sign-in still works; this module registers Web, which needs no retry. Do not add a client secret to an SPA registration — Entra refuses credentials and `Origin` in the same request |
| Hub refuses to start, names the issuer | `curl` the `discovery_url` output from the hub. cloop's startup preflight fetches exactly that, so a failure here is DNS, egress or a proxy — not cloop |
| Sign-in works, everything is read-only | The user holds no app role and got `default_role`. Check the `roles` claim at <https://jwt.ms> |
| Sign-out lands on a Microsoft page | The bare origin (with trailing slash) is not a registered redirect URI |
| Disabling a user does not end their session | No refresh token: `offline_access` missing from `ui.oidc.scopes`, or `CLOOP_SECRET_KEY` unset — or no provisioning, which ends it at the next cycle without one |
| Provisioning job in quarantine, logs show 401 | The hub refused the credential: revoked, or rotated and the grace period ran out. Rotate, apply, then **Restart provisioning** |
| Provisioning job in quarantine, logs show 404 on every request | The hub serves `/scim/v2` only with `ui.oidc` enabled — or `scim_base_address` is not the hub's external URL |
| Provisioning logs show 429 | The credential's rate limit (`ui.oidc.scim.rate_limit_per_minute`, default 600/min). Entra paces on `Retry-After`; raise the limit for a large first cycle |
| A disabled user keeps working after a cycle | Not matched: `cloop hub scim status` counts unmatchable and ambiguous users — usually `match_claim: oid` without the `objectId` → `externalId` mapping |

## See also

- [Configuration reference](../../../docs/reference/configuration.md) — every `ui.oidc` key
- [Security model](../../../docs/security/model.md) — the role ladder and what each permission covers
- [Deploying the hub](../../README.md) — image, compose stack, Helm chart
