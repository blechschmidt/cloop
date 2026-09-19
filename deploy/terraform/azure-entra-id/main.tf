# A Microsoft Entra ID application registration that cloop can sign users in
# against, shaped by what cloop actually does with the token rather than by
# what an app registration usually looks like.
#
# Four things drive every decision below, and each is a property of this
# codebase, not a preference:
#
#   1. cloop uses the authorization-code flow with PKCE, and by default holds
#      NO CLIENT SECRET. pkg/oidcauth sends code_challenge_method=S256 on every
#      authorization request and treats an empty secret as the public-client
#      configuration, presenting only its client_id at the token endpoint. So
#      the default registration here puts the redirect URIs on Entra's
#      public-client ("Mobile and desktop applications") platform and creates
#      no password — see the client_type variable, which can put this back to a
#      "Web" platform registration with a secret.
#
#      Never an SPA: Entra refuses to redeem a code for an spa-typed redirect
#      URI unless the request carries an Origin header (AADSTS9002327), and the
#      hub redeems it server-side from Go, not from the browser. The
#      public-client platform has no such gate.
#
#   2. cloop PINS THE ISSUER. pkg/oidcauth compares the discovery document's
#      `issuer` and the ID token's `iss` against the configured value, both for
#      equality. A multi-tenant registration issues tokens whose `iss` names
#      the signing-in user's home tenant, which can never equal one configured
#      string — so the registration is single-tenant (AzureADMyOrg) and the
#      module has no knob to make it otherwise.
#
#   3. cloop AUTHORIZES ON THE `roles` CLAIM. Entra puts app role assignments
#      there verbatim, and idClaims.roleValues() reads exactly that claim. So
#      the four cloop roles are declared as app roles and bound with
#      `claim: role`, rather than routed through group object IDs.
#
#   4. cloop RE-ASKS THE IDP. Session revalidation and the claim-freshness gate
#      above operator both use the refresh token from sign-in. Entra issues one
#      only when `offline_access` is requested, and cloop sends exactly the
#      scopes it is configured with — so the rendered config below asks for it.
#      Drop it and IdP-side revocation silently stops working: a session ends
#      only when one of the two timeouts fires.

data "azuread_client_config" "current" {}

# Microsoft Graph's own service principal, read rather than hard-coded.
#
# The delegated permissions below are identified by UUID in the API. Those
# UUIDs are stable and every example on the internet inlines them, which is
# precisely why they are worth not inlining: a literal
# "37f7f235-527c-4136-accd-4a02d197296e" in a required_resource_access block is
# unreviewable. Resolving them by name through the tenant's own Graph service
# principal makes the intent legible and survives a tenant where Graph's app ID
# is not the one you memorised.
data "azuread_application_published_app_ids" "well_known" {}

# Read, not created: Graph's service principal already exists in every tenant,
# and this module needs nothing from it but the name-to-UUID map of its
# delegated permission scopes.
data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

locals {
  # The hub's OIDC callback. This is not a convention the operator may choose:
  # it is the literal route pkg/ui registers ("GET /auth/callback"), and
  # tests/docs/terraform_azure_test.go asserts that this string is still a real
  # route in the hub's table.
  callback_path = "/auth/callback"

  # Public by default: no secret to mint, rotate, distribute or revoke, with
  # PKCE carrying what the secret otherwise would.
  is_public = var.client_type == "public"

  # null means "follow the client type", which is what lets the default be
  # secretless without making an operator who picks client_type =
  # "confidential" also remember to ask for the credential that choice implies.
  # An explicit false still means "confidential, credential supplied out of
  # band" — a certificate or a federated identity credential.
  create_secret = var.create_client_secret != null ? var.create_client_secret : !local.is_public

  # Redirect URIs, and why there are two per hub.
  #
  # The callback is the obvious one. The bare origin — WITH its trailing slash
  # — is the post-logout landing page: Authenticator.postLogoutRedirect()
  # builds "scheme://host/" from the configured redirect URL and sends it to
  # Entra as post_logout_redirect_uri. Entra only honours a post-logout URI
  # that is registered on the application; unregistered, sign-out dead-ends on
  # a generic Microsoft "you're signed out" page instead of returning to cloop.
  # The trailing slash is part of the match, so it is part of the value here.
  derived_redirect_uris = flatten([
    for base in var.hub_base_urls : [
      "${base}${local.callback_path}",
      "${base}/",
    ]
  ])

  redirect_uris = distinct(concat(local.derived_redirect_uris, var.extra_redirect_uris))

  # The issuer cloop must be configured with, and the discovery document its
  # startup preflight will fetch. The /v2.0 suffix is load-bearing: the v1.0
  # endpoint issues tokens whose `iss` is https://sts.windows.net/<tid>/, which
  # would not equal this and would fail validation on every sign-in.
  tenant_id     = data.azuread_client_config.current.tenant_id
  issuer        = "https://login.microsoftonline.com/${local.tenant_id}/v2.0"
  discovery_url = "https://login.microsoftonline.com/${local.tenant_id}/v2.0/.well-known/openid-configuration"

  # cloop's role ladder, in ascending order of privilege. The app role `value`
  # is what lands in the `roles` claim, so these strings are also the values
  # the rendered role_mappings below bind on — which is why they are cloop's
  # own role names and not decorated with a prefix. The token's audience is
  # this application, so a bare "admin" cannot be confused with some other
  # application's "admin".
  app_roles = {
    viewer = {
      display_name = "cloop viewer"
      description  = "Read projects and the executor fleet. Cannot start a run or change anything."
    }
    operator = {
      display_name = "cloop operator"
      description  = "Everything a viewer may do, plus start and stop runs and mutate tasks."
    }
    maintainer = {
      display_name = "cloop maintainer"
      description  = "Everything an operator may do, plus grant and revoke secrets and write configuration."
    }
    admin = {
      display_name = "cloop admin"
      description  = "Every permission, including managing executors and users and reading the audit trail."
    }
  }

  # App role IDs, derived rather than random.
  #
  # Entra keys an assignment by role ID. If an ID changes, the old role is
  # deleted and every assignment against it goes with it — users silently lose
  # access on an apply that looked like a no-op. uuidv5 makes the ID a pure
  # function of the role name, so it is identical on every apply, in every
  # tenant, and after a `terraform state rm`. That is worth more here than the
  # unpredictability random_uuid would give, which nothing needs.
  app_role_ids = {
    for role, _ in local.app_roles :
    role => uuidv5("url", "https://cloop.dev/entra/app-roles/${role}")
  }

  # Whether an app role may be held by a service principal as well as a user.
  allowed_member_types = var.allow_service_principal_roles ? ["User", "Application"] : ["User"]

  # (role, principal) pairs, flattened into the map azuread_app_role_assignment
  # needs. Keys are stable strings rather than indexes so that removing one
  # group from the middle of a list does not re-key — and therefore destroy and
  # recreate — everybody else's assignment.
  role_assignment_pairs = merge([
    for role, spec in var.role_assignments : merge(
      {
        for oid in spec.group_object_ids :
        "${role}/group/${oid}" => { role = role, principal_object_id = oid }
      },
      {
        for oid in spec.user_object_ids :
        "${role}/user/${oid}" => { role = role, principal_object_id = oid }
      },
    )
  ]...)
}

# ---------------------------------------------------------------- application

resource "azuread_application" "cloop" {
  display_name = var.display_name
  description  = var.description
  owners       = var.owners
  tags         = var.tags

  # Single-tenant. See note 2 in the header: cloop pins the issuer, and no
  # other audience produces a constant one.
  sign_in_audience = "AzureADMyOrg"

  # False under BOTH client types, and it is not the knob that makes this a
  # public client — the registered *type of the redirect URI* is, and that is
  # decided by which block below carries local.redirect_uris.
  #
  # Entra consults this flag only when it cannot infer the client type from a
  # redirect URI, which means only for the flows that have none: resource owner
  # password credentials, device code, Windows integrated auth. cloop uses none
  # of them. Setting it true would therefore change nothing about sign-in while
  # newly permitting ROPC and device code against this registration, so it
  # stays false even on a public client, where the name most invites flipping
  # it.
  fallback_public_client_enabled = false

  # Only emitted when the operator opts in; null leaves the claim off
  # entirely. See the emit_group_claims variable for why the default is off.
  group_membership_claims = var.emit_group_claims ? var.group_membership_claims : null

  # The redirect URIs live in exactly one of the two blocks below, and which
  # one is the entire public-vs-confidential decision. Entra classifies the
  # request by the type of the redirect URI it carries, so a Web-typed URI
  # demands a client credential (AADSTS7000218 without one) and an
  # InstalledClient-typed URI does not.
  #
  # An ordinary https:// URI is legal on the public-client platform — the
  # localhost/nativeclient values in Microsoft's docs are recommendations, not
  # an allowlist, and Microsoft's own App Service guide registers an
  # https://...authentication callback there.
  web {
    homepage_url = var.hub_base_urls[0]

    # Empty on a public client: leaving even one Web-typed URI registered would
    # be harmless for the callback but pointless, and having the list follow
    # the client type keeps the portal showing exactly one platform.
    redirect_uris = local.is_public ? [] : local.redirect_uris

    # Front-channel logout is deliberately NOT configured. cloop's sign-out
    # route is "POST /auth/logout"; Entra would call a logout URL with a GET,
    # which that route answers with 405. Sign-out works through the RP-initiated
    # path instead — the dashboard POSTs to cloop, then follows the
    # end_session_endpoint URL cloop hands back.
    #
    # logout_url = ... # do not set: see above

    implicit_grant {
      # Both off. cloop uses the authorization-code flow and reads the ID token
      # from the token endpoint response; an implicit grant here would be an
      # additional way to obtain a token that nothing in cloop needs.
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  # "Mobile and desktop applications" in the portal, InstalledClient in the
  # manifest. Present only on a public client — an empty block would still
  # register the platform.
  dynamic "public_client" {
    for_each = local.is_public ? [1] : []
    content {
      redirect_uris = local.redirect_uris
    }
  }

  # Evaluated on every plan because this resource always exists, which is why
  # the check lives here rather than on the password: that one is counted out
  # to zero in precisely the case being guarded, so its own precondition would
  # never run.
  lifecycle {
    precondition {
      condition     = !(local.is_public && coalesce(var.create_client_secret, false))
      error_message = "create_client_secret = true needs client_type = \"confidential\". Entra refuses to redeem a code with a client credential when the redirect URI is registered as a public client, so the secret would not merely be unused — it would be a credential that cannot be presented. Either drop create_client_secret, or set client_type = \"confidential\" to register the callback on the Web platform."
    }
  }

  api {
    # Governs the format of access tokens issued FOR this application when it
    # is called as a resource. cloop is never called that way — it reads the ID
    # token — so this is hygiene: it makes a v2.0-only registration, so nothing
    # can later obtain a v1.0 access token against it by accident.
    requested_access_token_version = 2
  }

  # The four cloop roles, as Entra app roles.
  dynamic "app_role" {
    for_each = local.app_roles
    content {
      id                   = local.app_role_ids[app_role.key]
      value                = app_role.key
      display_name         = app_role.value.display_name
      description          = app_role.value.description
      allowed_member_types = local.allowed_member_types
      enabled              = true
    }
  }

  optional_claims {
    id_token {
      # `email` is not in a v2.0 ID token by default for a managed user; it
      # arrives either via the `email` scope or via this optional claim.
      # Requesting it here as well as in the scopes is not redundant: it means
      # a deployment that narrows ui.oidc.scopes still gets the claim, so
      # admin_emails and any `claim: email` mapping do not quietly stop
      # matching.
      #
      # It still has no value for a managed user with no `mail` attribute, and
      # Entra's own guidance is not to authorize on it. Bind on app roles.
      name      = "email"
      essential = false
    }
  }

  required_resource_access {
    resource_app_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]

    dynamic "resource_access" {
      # openid          — the flow itself
      # profile         — `name` and `preferred_username`, shown in the UI
      # email           — the `email` claim (see optional_claims above)
      # offline_access  — the refresh token, without which cloop can never
      #                   re-ask Entra whether this user is still who they
      #                   were. See note 4 in the header.
      for_each = toset(["openid", "profile", "email", "offline_access"])
      content {
        id   = data.azuread_service_principal.msgraph.oauth2_permission_scope_ids[resource_access.key]
        type = "Scope" # delegated, not application
      }
    }
  }
}

# ---------------------------------------------------------- service principal

# The tenant-local half of the registration: assignments hang off this object,
# not off the application.
resource "azuread_service_principal" "cloop" {
  client_id = azuread_application.cloop.client_id
  owners    = var.owners

  # WindowsAzureActiveDirectoryIntegratedApp is the magic tag that lists the
  # service principal under Enterprise Applications and surfaces it in the My
  # Apps portal — without it the app is administrable but invisible to the
  # people who have to find it. The provider also exposes this as
  # `feature_tags { enterprise = true }`, but that block and `tags` are
  # mutually exclusive, and custom tags are worth more than the shorthand.
  tags = distinct(concat(var.tags, ["WindowsAzureActiveDirectoryIntegratedApp"]))

  description = var.description

  # Deny-by-default at the identity provider, mirroring cloop's own
  # default_role: none. See the variable for the failure mode this produces
  # (AADSTS50105) and why a legible refusal beats an empty dashboard.
  app_role_assignment_required = var.require_app_role_assignment

  # Where Entra sends a user who launches cloop from the My Apps portal.
  login_url = var.hub_base_urls[0]
}

# --------------------------------------------------------------- app roles

resource "azuread_app_role_assignment" "cloop" {
  for_each = local.role_assignment_pairs

  app_role_id         = local.app_role_ids[each.value.role]
  principal_object_id = each.value.principal_object_id
  resource_object_id  = azuread_service_principal.cloop.object_id
}

# ------------------------------------------------------------------- secret

# The rotation clock.
#
# time_rotating holds a single date still until it falls due, then advances it.
# That stillness is the whole point: an end_date computed from timestamp()
# would differ on every plan, so Terraform would rotate the credential — and
# break the running hub — every time anyone ran it.
resource "time_rotating" "client_secret" {
  count = local.create_secret ? 1 : 0

  rotation_days = var.client_secret_rotation_days
}

resource "azuread_application_password" "cloop" {
  count = local.create_secret ? 1 : 0

  # 3.x takes the application's resource ID (/applications/<object id>), not
  # its client ID. Passing .client_id here is the most common 2.x→3.x
  # migration error and fails at apply with an unhelpful parse message.
  application_id = azuread_application.cloop.id

  display_name = "cloop hub (terraform)"

  # Expiry trails the rotation date by the grace window, so a pipeline that
  # runs a few days late finds a credential that still works. Without the
  # margin, expiry and rotation coincide and being late is an outage.
  end_date = timeadd(
    time_rotating.client_secret[0].rotation_rfc3339,
    "${var.client_secret_grace_days * 24}h",
  )

  # Two triggers, two purposes. The rotating resource's ID changes when the
  # schedule falls due; the token changes when a human decides it must rotate
  # now. Either mints a new secret, and in both cases Terraform creates the
  # replacement and destroys the old one within one apply — so the hub has to
  # be restarted with the new value promptly.
  rotate_when_changed = {
    schedule = time_rotating.client_secret[0].id
    forced   = var.client_secret_rotation_token
  }
}
