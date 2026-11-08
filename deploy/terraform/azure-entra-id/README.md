# cloop SSO on Microsoft Entra ID

This Terraform module creates the Entra ID (Azure AD) application a cloop hub
signs users in with, and prints the `ui.oidc` block to paste into the hub's
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

No secret is needed. By default the registration is a **public client** and
the hub authenticates the code exchange with PKCE, so there is nothing to
rotate, copy to each replica, or revoke after a leak. For a client secret, set
`client_type = "confidential"` (see [Credentials](#credentials)).

The module works as it is. The sections below explain its less obvious
settings, each of which follows from how cloop uses the token.

---

## What it creates

| Resource | Why |
| --- | --- |
| `azuread_application` | The registration: public-client platform by default, single-tenant, four app roles, the `email` optional claim, four delegated Graph scopes |
| `azuread_service_principal` | The enterprise app. Assignments and Conditional Access attach here, not to the application |
| `azuread_application_password` | The client secret, only when `client_type = "confidential"` |
| `time_rotating` | The secret's rotation schedule, fixed between rotations so plans show no changes |
| `azuread_app_role_assignment` | One per (role, group-or-user) pair you declare |
| `azuread_application_from_template` | The provisioning application, only with `scim_provisioning` (see [Provisioning](#provisioning-scim)) |
| `azuread_synchronization_secret` | Its connection: the hub's `/scim/v2` URL, the hub's SCIM credential and the scope |
| `azuread_synchronization_job` | The provisioning job, started on creation |
| `azuread_app_role_assignment` (provisioning) | One per principal in the job's scope |

---

## Five things that are not obvious

Each of these fails with a symptom that doesn't point to the cause. The
defaults handle all five.

### 1. Single-tenant, and there is no knob

cloop pins the issuer: `pkg/oidcauth` requires the discovery document's
`issuer` and the ID token's `iss` to equal the configured string. A
multi-tenant registration issues tokens whose `iss` names the signing-in user's
home tenant, so no single configured value can match them all. The module sets
`sign_in_audience = "AzureADMyOrg"` and has no input to change it.

For the same reason, the issuer is `https://login.microsoftonline.com/<tenant>/v2.0`,
never `.../common/v2.0`.

### 2. The `/v2.0` suffix is load-bearing

The v1.0 endpoint issues tokens whose `iss` is `https://sts.windows.net/<tid>/`.
With a v1.0 issuer configured, every sign-in appears to succeed at Microsoft
and then fails validation. The `issuer` output always ends in `/v2.0`, and a
hand-written issuer must too.

### 3. Two redirect URIs per hub, and the trailing slash matters

`https://cloop.example.com/auth/callback` is the obvious one: the route
`pkg/ui` serves, checked against the hub's route table by
`tests/docs/terraform_azure_test.go`.

`https://cloop.example.com/` is the one people miss. On sign-out, cloop sends
Entra a `post_logout_redirect_uri` of `scheme://host/`, with the trailing
slash, and Entra only follows a post-logout URI that is registered. Otherwise
sign-out ends on a generic Microsoft page instead of the dashboard. The module
registers both.

### 4. `offline_access`, or IdP revocation silently stops working

cloop requests only the scopes it is configured with (default
`openid profile email`), and Entra issues a refresh token only when
`offline_access` is one of them. Without a refresh token, two checks stop
working and nothing reports an error:

- **`refresh_interval_minutes`**, the background re-check that ends a session
  after the IdP disables the account.
- **`max_claim_age_minutes`**, the synchronous re-check before any action above
  operator (granting a secret, managing a user, writing config).

Sign-in keeps working, and a disabled account keeps its session until one of
the two timeouts fires. So the rendered config requests `offline_access`, the
registration requests the matching Graph permission, and a test fails if
either loses it.

The hub also stores the refresh token only when `CLOOP_SECRET_KEY` is set (see
[the security model](../../../docs/security/model.md)).

### 5. App roles, not group claims

cloop can bind roles to a `group` claim, but on Entra that works worse:

- Values are group object IDs (GUIDs), not names, unless the group is synced
  from on-premises AD.
- The claim is capped. Past 200 groups in a JWT, Entra omits `groups` and adds
  `_claim_names`/`_claim_sources` pointing at Microsoft Graph. cloop doesn't
  follow that reference: it reads no groups and falls back to `default_role`,
  without an error. Long-serving staff are demoted first, because they are in
  the most groups.

App roles have neither problem: the value arrives unchanged in the `roles`
claim, means what the person may do in this application, and the same test
checks the four roles against `pkg/authz`'s ladder.

`emit_group_claims = true` turns the group claim on anyway. The claim then
defaults to `ApplicationGroup` (only groups assigned to this application), the
only setting that keeps it bounded.

---

## Deny-by-default on both sides

`require_app_role_assignment` (default `true`) makes Entra refuse a token to
anyone without an app role. `cloop_default_role` (default `none`) makes cloop
grant nothing to an identity that matches no mapping.

So after a fresh apply nobody can sign in, including you, until you grant
access. That is intended, so that the whole directory isn't let in while
someone works out the role mappings. An unassigned user gets **AADSTS50105**,
which names the application and is easy to search for, rather than an empty
dashboard.

Assigning an app role to a group requires Microsoft Entra ID P1 or above. On
the Free tier, use `user_object_ids`, or set `emit_group_claims = true` and
bind on the group claim in cloop.

---

## Credentials

By default there are none. `client_type = "public"` registers the redirect URIs
on Entra's public-client platform ("Mobile and desktop applications" in the
portal, `InstalledClient` in the manifest), and Entra redeems a code presented
with a `client_id` and a PKCE verifier, without any credential.

Three points about this are often misunderstood:

- **An ordinary `https://` URI is allowed there.** The `localhost` and
  `nativeclient` values in Microsoft's docs are recommendations, not an
  allowlist. Microsoft's own App Service guide registers an
  `https://…/.auth/login/aad/callback` on that platform.
- **It is not the "Allow public client flows" toggle.** That flag
  (`fallback_public_client_enabled`, `isFallbackPublicClient`) applies only to
  flows without a redirect URI, such as ROPC and device code. It does nothing
  for sign-in and enables those flows. The module leaves it `false` under both
  client types.
- **It is not an SPA registration.** Entra refuses to redeem a code for an
  `spa`-typed URI unless the request carries an `Origin` header
  (**AADSTS9002327**), and the hub redeems server-side, from Go. SPA
  registrations also get 24-hour refresh tokens.

What you give up: this registration cannot obtain app-only tokens (client
credentials) or use on-behalf-of. cloop needs neither, because it reads only
the ID token.

Set `client_type = "confidential"` where a policy requires client
authentication. That registers the URIs on the Web platform and creates a
secret, which you supply to the hub yourself:

```console
$ export CLOOP_OIDC_CLIENT_SECRET=$(terraform output -raw client_secret)
```

With `create_client_secret = false` as well, no secret is created and you
supply a certificate or federated identity credential yourself. It is still a
confidential client. `create_client_secret = true` on a public client fails at
plan time: Entra does not accept a credential for a code issued to a
public-client URI, so the secret could never be presented.

### Rotation

Applies to `client_type = "confidential"` only.

The client secret rotates on a schedule (`client_secret_rotation_days`,
default 180) and expires `client_secret_grace_days` (default 30) later. The
gap is the margin for a pipeline that runs late.

Rotation happens on the first apply after the due date, so it is only as
regular as your Terraform runs. Put `client_secret_expires_at` in a calendar.
An expired secret fails every new sign-in with **AADSTS7000222** while existing
sessions keep working, so the outage builds up gradually and is easy to
misread.

For a suspected leak, change `client_secret_rotation_token`. That rotates at
once with no grace period, so restart the hub with the new value promptly.

The secret is in Terraform state. Use a backend that encrypts it.

---

## Consent

Visit `admin_consent_url` once, as a Privileged Role Administrator, to consent
for the whole tenant. Otherwise each user is asked on first sign-in, and
`offline_access` is the scope users most often decline. Declining it turns off
IdP revocation for that user, and nothing reports it.

---

## Conditional Access

The module creates no policies, because they are tenant-wide and belong with
your other CA policies. Scope them to `service_principal_object_id`. Requiring MFA for cloop is a reasonable use,
since the hub can grant credentials to a sandbox and attach to a running one.

---

## Provisioning (SCIM)

With sign-in alone, a person disabled in Entra keeps a working hub session
until cloop next checks with Entra, keeps their API tokens until someone
revokes them, and keeps any sandbox lease they hold. Provisioning closes that
gap without anyone having to act. Entra's provisioning service tells the hub
about every account in scope, and when one is disabled, deleted or unassigned
it sends `active: false`. The hub then suspends the person in one request: a
deny binding on their identity, and their sessions, API tokens, glasses links,
sandbox leases and running tasks ended.

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
   once (**Settings → Provisioning** does the same in the dashboard). Apply
   again with it as `scim_secret_token`, and merge the `scim:` block that now
   appears in `cloop_config_yaml`.

Microsoft's provisioning service calls the hub over the internet, so the hub
must be reachable from there, not only from users' browsers as for sign-in.

### Why a second application

Entra runs a provisioning job only on an enterprise application created from a
template. The sign-in registration is a plain app registration, and recreating
it from a template would replace it, client ID and assignments included, so the
module creates a second application from Entra's non-gallery template. Nobody
signs in with it. It holds the job, the connection and the assignments that
form the job's scope, **Sync only assigned users and groups**
(`SyncAll = false`). By default everyone in `role_assignments` is assigned,
since the people who can sign in are the people to deprovision, and
`scim_provisioning.group_object_ids` and `user_object_ids` add more.

### What Entra sends, and what the hub does

| In Entra | Sent | On the hub |
| --- | --- | --- |
| Account assigned (directly or through a group) | `POST /Users` | A provisioned user, with no access by itself |
| Sign-in blocked, account deleted, unassigned, or out of a scoping filter | `PATCH active: false` | **Suspended**: a deny binding, and sessions, API tokens, glasses links, leases and running tasks end. Grants over their personal secrets are suspended. Memberships and stored credentials are kept |
| Re-enabled, restored or reassigned | `PATCH active: true` | The suspension's deny binding and grant suspensions are lifted. What ended stays ended, so they sign in again |
| Hard-deleted (30 days after deletion, or purged from the recycle bin) | `DELETE /Users/{id}` | Full offboarding, as `cloop hub user offboard`, except that a legal hold keeps their credentials |
| Group assigned; members added or removed | `POST /Groups`, `PATCH members` | Membership becomes the `scim_group` claim, read at every authorization decision |

This has two consequences. Entra sends a `DELETE` only for a user it still manages, so
an unassigned user stays suspended indefinitely.
`scim_provisioning.offboard_after_days` runs the full offboarding for anyone
kept deactivated that long. And Entra works in cycles, about every 40 minutes,
so a disable reaches the hub at the next cycle, not when it is made.
**Provision on demand** on the provisioning application pushes one user now.
To cut someone off within the next five minutes, use the dashboard's
offboarding.

### Matching a provisioned user to a person

The hub has to know which signed-in identity a provisioned user is. The
rendered `ui.oidc.scim.match_claim` decides:

- **`preferred_username`** (the module's default): Entra's default mapping
  provisions `userName` from the `userPrincipalName`, which the ID token
  carries as `preferred_username`. No portal changes are needed, and guests
  work: Entra strips the `#EXT#` suffix from a guest's UPN before provisioning
  it.
- **`oid`**: the object ID, which never changes and is never reused. Entra's
  default mapping sends `mailNickname` as `externalId`, so this needs a portal
  step the provider cannot take: on the provisioning application, under
  **Provisioning → Attribute mapping → Provision Microsoft Entra ID Users →
  externalId**, change the source attribute to `objectId` and save. Until then
  the hub counts every user as unmatchable, and `cloop hub doctor` says so.
- **`email`**: the `mail` attribute, sent as the work email. Users without a
  mailbox have none and cannot be matched.

If a provisioned user could be either of two hub identities, the hub does not
guess: it denies that claim value only, and gives neither identity the user's
groups.

### Binding roles to provisioned groups

Provisioned groups become a claim that role mappings can name, without
`emit_group_claims` and without the 200-group overage:

```hcl
cloop_extra_role_mappings = [
  { claim = "scim_group", value = "Payments", role = "maintainer", project = "payments" },
]
```

The value is the group's display name or its object ID (Entra's default group
mapping sends the object ID as `externalId`). Membership is read at every
decision, so removing someone from the group in Entra demotes them on their
next request after the next cycle. Only assigned groups are provisioned, so
also assign the group to the provisioning application
(`scim_provisioning.group_object_ids`).

### What the provider cannot set

Terraform leaves these to you. Set them on the provisioning application in
the portal:

- **Notification email** (Provisioning → Overview → Properties): an address
  Entra tells when the job goes into quarantine, which is how a revoked or
  expired hub credential shows up.
- **Accidental deletions prevention** (same place): pauses the job when one
  cycle would deactivate more users than a threshold, as unassigning the wrong
  group would.
- **Visible to users** (Properties): set it to No. The provisioning application
  has no sign-in of its own, so its My Apps tile leads nowhere.

The module's synchronization secret holds the endpoint, the credential and the
scope. Entra stores them as one set and the provider writes them as one, so
change the scope here, not in the portal.

### Rotating the credential

```console
$ cloop hub scim credential rotate entra --grace 1h    # on the hub
$ TF_VAR_cloop_scim_token=cloop_scim_… terraform apply  # within the hour
```

The old credential keeps working for the grace period, so a cycle in progress
does not fail. Entra never returns the credential, so it is in Terraform state,
and the state backend must encrypt.
`cloop hub scim credential revoke entra --reason "…"` stops provisioning at
once: the next cycle fails with 401 and the job goes into quarantine.

---

## Key Vault for the sealing keys (`modules/key-vault-kms`)

A hub can keep the key-encryption keys of its secret store in Key Vault instead
of deriving them from `CLOOP_SECRET_KEY` (`secrets.kms`). Each key is random,
and the hub's database keeps only the ciphertext Key Vault's `wrapKey` made of
it, so a copy of the database and the key file opens nothing without the vault.
The hub reaches the vault through the AKS KMS plugin (the Kubernetes KMS v2
plugin the API server uses for its own encryption at rest), run as a sidecar by
the Helm chart.

[`modules/key-vault-kms`](modules/key-vault-kms) creates what that needs, in a
vault you already run:

* **The key**: RSA 3072, HSM-protected by default (`hsm = false` for a Standard
  vault), limited to the `wrapKey` and `unwrapKey` operations, with an optional
  rotation policy (`rotate_after_days`).
* **The hub identity's permission**: *Key Vault Crypto Service Encryption User*
  (read the key's metadata, wrap, unwrap) for `principal_object_id`, scoped to
  that one key. On a vault that still uses access policies
  (`authorization = "access_policy"`), it is get, wrapKey and unwrapKey on the
  vault's keys. Never decrypt, never secrets. Removing it revokes the hub's
  access.

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

It is a separate module because Key Vault, an Azure Resource Manager
resource, needs the `azurerm` provider. In this module it would make every
caller configure `azurerm`, subscription and all, whether they want a KMS or
not. [examples/complete](examples/complete) uses both.

Outputs: `helm_values_yaml` (the chart's `kms` block; pin the plugin image, and
create the `kms-azure-json` Secret holding the plugin's `azure.json`),
`cloop_secrets_yaml` (the `secrets` section for a hub installed without the
chart), `kms_plugin_args`, `key_id`, `key_version`, `key_name`, `key_vault_name`
and `key_resource_id`.

Two settings belong to the vault, and both matter. **Soft delete and purge
protection**: a purged key takes every secret the hub sealed with it, and no
database restore brings them back. **Keeping old key versions** until
`cloop hub key list` shows them on no live key: the hub rewraps onto a new
version as soon as the plugin points at it, but an older backup still needs
the old one. The [runbook](../../../docs/operations/runbook.md#keys-in-a-kms)
covers moving a running hub onto the key.

## Inputs

| Name | Type | Default | |
| --- | --- | --- | --- |
| `hub_base_urls` | `list(string)` | none | **Required.** External hub URLs, no trailing slash |
| `display_name` | `string` | `"cloop hub"` | Shown in the portal and on the consent screen |
| `description` | `string` | … | Stored on the application object |
| `owners` | `list(string)` | `[]` | Directory principals who may administer the app |
| `tags` | `list(string)` | `["cloop", "terraform-managed"]` | Entra tags are plain strings |
| `extra_redirect_uris` | `list(string)` | `[]` | For example a developer's `http://localhost:8080/auth/callback` |
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
| `cloop_admin_emails` | `list(string)` | `[]` | Break-glass. Prefer the `admin` app role |
| `cloop_extra_role_mappings` | `list(object)` | `[]` | Project- and executor-scoped grants |
| `scim_provisioning` | `object` | `null` | Turns on [provisioning](#provisioning-scim). `{}` takes every default |
| `scim_secret_token` | `string` (sensitive) | `null` | The credential `cloop hub scim credential create` printed |

## Outputs

`cloop_config_yaml` is the one you want. The others are fields of it or values
you need when sign-in fails: `client_id`, `client_type`, `client_secret`,
`client_secret_expires_at`, `issuer`, `discovery_url`, `redirect_url`,
`redirect_uris`, `tenant_id`, `application_object_id`,
`service_principal_object_id`, `app_role_ids`, `admin_consent_url` and
`app_role_assignment_required`. With provisioning, `scim_base_address`,
`provisioning_service_principal_object_id`, `provisioning_job_id` and
`provisioning_app_role_id` show where Entra provisions and what it was given.
`terraform output` describes each.

---

## Testing

The module has a suite that needs no Azure tenant:

```console
$ terraform init -backend=false
$ terraform test
Success! 26 passed, 0 failed.
```

It mocks the provider, so only an apply against a real tenant shows what Entra
accepts. It covers everything decidable from the configuration: both
redirect URIs and which platform block holds them, the `/v2.0` issuer, the
rendered scopes, the derived app role IDs, and that input validation refuses
the URLs Entra would refuse later, less clearly.

If you trim it, keep the platform assertions. Public versus confidential
depends only on whether the URIs are in `public_client` or `web`, and the
computed `redirect_uris` output is the same either way, so nothing else in the
suite can tell the two registrations apart.

The joins to cloop itself are checked from Go, in
[`tests/docs/terraform_azure_test.go`](../../../tests/docs/terraform_azure_test.go),
where both sides are visible. It checks that:

- the callback path is a route `pkg/ui` still serves;
- the four app roles are `pkg/authz`'s ladder;
- the rendered YAML keys are fields of `config.OIDCConfig`;
- the environment variable is the one `pkg/config` reads;
- every scope the config requests is a permission the registration was granted;
- for provisioning, the SCIM path is where the hub serves SCIM, the credential
  pattern accepts what the hub's parser accepts, and every match claim is one
  the hub starts with.

`make terraform-test` runs both, and CI runs it.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| **AADSTS50011** redirect URI mismatch | `ui.oidc.redirect_url` differs from what is registered, usually because the hub is reached on a hostname not in `hub_base_urls` |
| **AADSTS50105** user not assigned | Expected: the user holds no app role. Assign one, or set `require_app_role_assignment = false` |
| **AADSTS7000218** request body must contain `client_assertion` or `client_secret` | The client type differs: the callback is on the Web platform, but the hub has no secret. Set `client_type = "public"` here, or export `CLOOP_OIDC_CLIENT_SECRET` on the hub |
| **AADSTS7000222** invalid client secret | The secret expired. Apply to rotate it, then restart the hub |
| **AADSTS9002327** tokens for the SPA client-type may only be redeemed cross-origin | A redirect URI is on the SPA platform. cloop now retries the exchange with an `Origin` header, so sign-in still works. This module registers the public-client platform (or Web, with `client_type = "confidential"`), and neither needs the retry. Don't add a client secret to an SPA registration: Entra refuses a credential and `Origin` together |
| Hub refuses to start, names the issuer | `curl` the `discovery_url` output from the hub's machine. cloop's startup preflight fetches that URL, so a failure there is DNS, egress or a proxy, not cloop |
| Sign-in works, everything is read-only | The user holds no app role and got `default_role`. Check the `roles` claim at <https://jwt.ms> |
| Sign-out lands on a Microsoft page | The bare origin (with trailing slash) is not a registered redirect URI |
| Disabling a user does not end their session | No refresh token (`offline_access` missing from `ui.oidc.scopes`, or `CLOOP_SECRET_KEY` unset), or no provisioning, which ends it at the next cycle even without one |
| Provisioning job in quarantine, logs show 401 | The hub refused the credential: revoked, or rotated and past its grace period. Rotate, apply, then **Restart provisioning** |
| Provisioning job in quarantine, logs show 404 on every request | The hub serves `/scim/v2` only with `ui.oidc` enabled, or `scim_base_address` is not the hub's external URL |
| Provisioning logs show 429 | The credential's rate limit (`ui.oidc.scim.rate_limit_per_minute`, default 600/min). Entra paces itself on `Retry-After`. Raise the limit for a large first cycle |
| A disabled user keeps working after a cycle | Not matched. `cloop hub scim status` counts unmatchable and ambiguous users. Usually `match_claim: oid` without the `objectId` → `externalId` mapping |

## See also

- [Configuration reference](../../../docs/reference/configuration.md): every `ui.oidc` key
- [Security model](../../../docs/security/model.md): the role ladder and what each permission covers
- [Deploying the hub](../../README.md): image, compose stack, Helm chart
