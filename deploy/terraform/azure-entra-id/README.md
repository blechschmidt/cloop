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

## Outputs

`cloop_config_yaml` is the one you want. The rest —`client_id`, `client_type`,
`client_secret`, `client_secret_expires_at`, `issuer`, `discovery_url`,
`redirect_url`, `redirect_uris`, `tenant_id`, `application_object_id`,
`service_principal_object_id`, `app_role_ids`, `admin_consent_url`,
`app_role_assignment_required` — are either fields of it or things you need
when a sign-in does not work. `terraform output` describes each.

---

## Testing

The module has a suite that needs no Azure tenant:

```console
$ terraform init -backend=false
$ terraform test
Success! 17 passed, 0 failed.
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
the one `pkg/config` reads, and that every scope the config requests is a
permission the registration was granted.

`make terraform-test` runs both, and CI runs that.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| **AADSTS50011** redirect URI mismatch | `ui.oidc.redirect_url` differs from what is registered — usually a hub reached on a different hostname than `hub_base_urls` |
| **AADSTS50105** user not assigned | Working as intended. Assign an app role, or set `require_app_role_assignment = false` |
| **AADSTS7000218** request body must contain `client_assertion` or `client_secret` | The two sides disagree about the client type: the callback is registered on the Web platform but the hub has no secret. Either `client_type = "public"` here, or export `CLOOP_OIDC_CLIENT_SECRET` there |
| **AADSTS7000222** invalid client secret | Expired. Apply to rotate, then restart the hub |
| **AADSTS9002327** tokens for the SPA client-type may only be redeemed cross-origin | A redirect URI got registered on the SPA platform. cloop redeems the code server-side, so it must be public-client or Web — this module never registers SPA |
| Hub refuses to start, names the issuer | `curl` the `discovery_url` output from the hub. cloop's startup preflight fetches exactly that, so a failure here is DNS, egress or a proxy — not cloop |
| Sign-in works, everything is read-only | The user holds no app role and got `default_role`. Check the `roles` claim at <https://jwt.ms> |
| Sign-out lands on a Microsoft page | The bare origin (with trailing slash) is not a registered redirect URI |
| Disabling a user does not end their session | No refresh token: `offline_access` missing from `ui.oidc.scopes`, or `CLOOP_SECRET_KEY` unset |

## See also

- [Configuration reference](../../../docs/reference/configuration.md) — every `ui.oidc` key
- [Security model](../../../docs/security/model.md) — the role ladder and what each permission covers
- [Deploying the hub](../../README.md) — image, compose stack, Helm chart
