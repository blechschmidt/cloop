# Unit tests for the module, run with `terraform test` and no Azure tenant.
#
# The provider is mocked, so nothing here proves Entra accepts the objects —
# only an apply against a real tenant does that. What it does prove is every
# claim the module makes that is decidable from its own configuration, and
# those are the ones that rot: that both redirect URIs are registered, that the
# issuer carries /v2.0, that the rendered cloop config asks for offline_access,
# that the four app roles match cloop's role ladder, and that the input
# validation refuses the URLs Entra would refuse later and less clearly.
#
#   cd deploy/terraform/azure-entra-id && terraform init -backend=false && terraform test
#
# `make terraform-test` runs it, and CI runs that.

mock_provider "azuread" {
  # The application's `id` is its Graph resource ID, and the provider parses it
  # rather than treating it as opaque — azuread_application_password rejects
  # anything that is not "/applications/<object id>". A generated mock value
  # fails that parse, so it is pinned here. (Which is itself worth knowing:
  # passing .client_id instead of .id is the classic 2.x→3.x mistake, and
  # this is the error it produces.)
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb"
      object_id = "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb"
      client_id = "cccccccc-0000-1111-2222-dddddddddddd"
    }
  }

  mock_resource "azuread_service_principal" {
    defaults = {
      object_id = "eeeeeeee-0000-1111-2222-ffffffffffff"
    }
  }

  mock_data "azuread_client_config" {
    defaults = {
      tenant_id = "11111111-2222-3333-4444-555555555555"
      object_id = "99999999-8888-7777-6666-555555555555"
      client_id = "00000000-1111-2222-3333-444444444444"
    }
  }

  mock_data "azuread_application_published_app_ids" {
    defaults = {
      result = {
        MicrosoftGraph = "00000003-0000-0000-c000-000000000000"
      }
    }
  }

  # Only the delegated scopes the module resolves by name. A real tenant
  # returns dozens; these four are the ones indexed in main.tf, and a lookup
  # for a key absent here fails the test — which is the point. Adding a scope
  # to required_resource_access without adding it here does not quietly pass.
  mock_data "azuread_service_principal" {
    defaults = {
      oauth2_permission_scope_ids = {
        openid         = "37f7f235-527c-4136-accd-4a02d197296e"
        profile        = "14dad69e-099b-42c9-810b-d002981feec1"
        email          = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
        offline_access = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182"
      }
    }
  }
}

variables {
  hub_base_urls = ["https://cloop.example.com"]
}

# ---------------------------------------------------------------- happy path

run "defaults_produce_a_working_registration" {
  command = apply

  assert {
    condition     = azuread_application.cloop.sign_in_audience == "AzureADMyOrg"
    error_message = "The registration must be single-tenant: cloop compares the ID token's iss against one configured issuer, and a multi-tenant app issues a different one per signing-in tenant."
  }

  # False on a public client too. This flag is consulted only for flows that
  # carry no redirect URI (ROPC, device code), so turning it on would not
  # affect sign-in at all while newly permitting those — the opposite of what
  # its name suggests, and the reason it is asserted rather than left alone.
  assert {
    condition     = azuread_application.cloop.fallback_public_client_enabled == false
    error_message = "fallback_public_client_enabled must stay false: it does not make this a public client (the redirect URI's platform does) and setting it would enable ROPC and device code against this registration."
  }

  # The public-vs-confidential decision, asserted where it is actually made.
  # Entra classifies a token request by the registered type of the redirect URI
  # it carries: a Web-typed URI demands a client credential and fails with
  # AADSTS7000218 without one. So "is this a public client" is precisely "are
  # the URIs in public_client and not in web", and nothing else in this file
  # can see that — output.redirect_uris is the same list either way.
  assert {
    condition     = length(azuread_application.cloop.public_client) == 1
    error_message = "The default must register a public-client platform; without it the callback is Web-typed and Entra refuses a secretless code exchange."
  }

  assert {
    condition     = contains(azuread_application.cloop.public_client[0].redirect_uris, "https://cloop.example.com/auth/callback")
    error_message = "The callback must be registered on the public-client platform, not merely present in the computed list."
  }

  assert {
    condition     = length(azuread_application.cloop.web[0].redirect_uris) == 0
    error_message = "No URI may stay Web-typed on a public client: one is enough for Entra to demand a credential the hub does not have."
  }

  # The default is secretless. This is the property the whole client_type
  # change exists for, so it is asserted on the defaults rather than only in
  # the opt-out test below.
  assert {
    condition     = length(azuread_application_password.cloop) == 0
    error_message = "The default registration must create no client secret; PKCE is what authenticates the code exchange."
  }

  assert {
    condition     = output.client_secret == null
    error_message = "There is no secret to output by default."
  }

  assert {
    condition     = output.client_type == "public"
    error_message = "The module must default to a public client."
  }

  # Both redirect URIs, and the bare origin's trailing slash, are exactly what
  # Authenticator.postLogoutRedirect() builds. Drop either and sign-in or
  # sign-out breaks in a way the portal will not explain.
  assert {
    condition     = contains(output.redirect_uris, "https://cloop.example.com/auth/callback")
    error_message = "The hub's OIDC callback is not registered as a redirect URI."
  }

  assert {
    condition     = contains(output.redirect_uris, "https://cloop.example.com/")
    error_message = "The hub's bare origin (with trailing slash) is not registered, so Entra will refuse the post_logout_redirect_uri cloop sends and sign-out will dead-end on a Microsoft page."
  }

  assert {
    condition     = output.issuer == "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
    error_message = "The issuer must be the v2.0 endpoint for the tenant; the v1.0 endpoint issues iss=https://sts.windows.net/<tid>/ and every sign-in would fail validation."
  }

  assert {
    condition     = output.discovery_url == "${output.issuer}/.well-known/openid-configuration"
    error_message = "The advertised discovery URL must be the one cloop's startup preflight actually fetches."
  }

  # Deny-by-default on both sides of the boundary.
  assert {
    condition     = azuread_service_principal.cloop.app_role_assignment_required == true
    error_message = "By default an unassigned user must be refused a token by Entra, not handed one and left on an empty dashboard."
  }

  assert {
    condition     = strcontains(output.cloop_config_yaml, "default_role: none")
    error_message = "The rendered cloop config must deny by default."
  }

  # The group claim is off unless asked for: see the emit_group_claims
  # variable for the 200-group overage this avoids.
  assert {
    condition     = azuread_application.cloop.group_membership_claims == null
    error_message = "group_membership_claims must be unset by default."
  }
}

# --------------------------------------------------------- the roles contract

run "app_roles_match_cloops_role_ladder" {
  command = apply

  assert {
    condition     = length(azuread_application.cloop.app_role) == 4
    error_message = "cloop has four assignable roles (viewer, operator, maintainer, admin); the registration must declare exactly those."
  }

  # The app role `value` is what Entra puts in the `roles` claim verbatim, and
  # what the rendered role_mappings bind on. If the two ever disagree, sign-in
  # succeeds and the user silently gets default_role.
  assert {
    condition = alltrue([
      for role in ["viewer", "operator", "maintainer", "admin"] :
      contains([for r in azuread_application.cloop.app_role : r.value], role)
    ])
    error_message = "Every cloop role must exist as an app role whose value is the role name."
  }

  assert {
    condition = alltrue([
      for role in ["viewer", "operator", "maintainer", "admin"] :
      strcontains(output.cloop_config_yaml, "{claim: role, value: \"${role}\", role: ${role}}")
    ])
    error_message = "The rendered config must bind every app role through the `roles` claim."
  }

  # Derived, not random: a changed app role ID deletes the role and every
  # assignment against it.
  assert {
    condition     = output.app_role_ids["admin"] == uuidv5("url", "https://cloop.dev/entra/app-roles/admin")
    error_message = "App role IDs must be a pure function of the role name so they never change under an apply."
  }

  assert {
    condition = alltrue([
      for r in azuread_application.cloop.app_role : r.allowed_member_types == toset(["User"])
    ])
    error_message = "By default only users hold cloop roles; service principals are opt-in via allow_service_principal_roles."
  }
}

run "service_principals_may_hold_roles_when_opted_in" {
  command = apply

  variables {
    allow_service_principal_roles = true
  }

  assert {
    condition = alltrue([
      for r in azuread_application.cloop.app_role :
      r.allowed_member_types == toset(["User", "Application"])
    ])
    error_message = "allow_service_principal_roles must widen every app role, not some of them."
  }
}

# ------------------------------------------------------- the refresh contract

run "the_rendered_config_requests_offline_access" {
  command = apply

  # Without offline_access Entra issues no refresh token, and cloop's session
  # revalidation and claim-freshness gate both go dark — a demotion at the IdP
  # then survives until one of the two timeouts fires. It is requested twice,
  # and both are load-bearing: as a Graph permission on the registration, and
  # as a scope in the authorization request cloop sends.
  assert {
    condition     = strcontains(output.cloop_config_yaml, "scopes: [openid, profile, email, offline_access]")
    error_message = "The rendered config must request offline_access, or IdP-side revocation never happens."
  }

  assert {
    condition = anytrue([
      for rra in azuread_application.cloop.required_resource_access :
      length([
        for ra in rra.resource_access : ra
        if ra.id == "7427e0e9-2fba-42fe-b0c0-848c9e6a8182" && ra.type == "Scope"
      ]) == 1
    ])
    error_message = "offline_access must be requested as a delegated Microsoft Graph permission on the registration."
  }

  # email arrives via the scope on v2.0, but a deployment that narrows
  # ui.oidc.scopes would lose it — and with it admin_emails and any
  # `claim: email` mapping. The optional claim keeps it in the token either way.
  assert {
    condition = anytrue([
      for oc in azuread_application.cloop.optional_claims :
      anytrue([for c in oc.id_token : c.name == "email"])
    ])
    error_message = "The email optional claim must be requested so the claim survives a narrowed scope list."
  }
}

# ------------------------------------------------------------- the config file

run "the_rendered_config_carries_no_secret" {
  command = apply

  variables {
    cloop_admin_emails = ["break-glass@example.com"]
  }

  # The YAML is meant to be committable. cloop reads CLOOP_OIDC_CLIENT_SECRET
  # in preference to the YAML field, so the credential never needs to be in it.
  assert {
    condition     = !strcontains(output.cloop_config_yaml, "client_secret:")
    error_message = "The rendered config must not contain a client_secret field; the secret belongs in CLOOP_OIDC_CLIENT_SECRET."
  }

  # On the default public client there is no secret at all, and the rendered
  # config has to say so. Silence reads as an omission to anyone who has
  # configured OIDC before, and sends them looking for a value that does not
  # exist.
  assert {
    condition     = !strcontains(output.cloop_config_yaml, "CLOOP_OIDC_CLIENT_SECRET")
    error_message = "A public-client config must not point at a secret variable there is nothing to put in."
  }

  assert {
    condition     = strcontains(output.cloop_config_yaml, "PKCE")
    error_message = "The rendered config should say what authenticates the code exchange when no secret does."
  }

  assert {
    condition     = strcontains(output.cloop_config_yaml, "      - \"break-glass@example.com\"")
    error_message = "admin_emails must be rendered, quoted, under the oidc block."
  }

  assert {
    condition     = strcontains(output.cloop_config_yaml, "redirect_url: \"https://cloop.example.com/auth/callback\"")
    error_message = "The rendered redirect_url must match the URI registered on the application."
  }
}

run "scoped_role_mappings_render" {
  command = apply

  variables {
    cloop_extra_role_mappings = [
      { claim = "group", value = "8a1b2c3d-0000-1111-2222-333344445555", role = "maintainer", project = "payments" },
      { claim = "sub", value = "abc123", role = "viewer" },
    ]
  }

  assert {
    condition     = strcontains(output.cloop_config_yaml, "{claim: group, value: \"8a1b2c3d-0000-1111-2222-333344445555\", role: maintainer, project: \"payments\"}")
    error_message = "A project-scoped extra mapping must render its project key."
  }

  assert {
    condition     = strcontains(output.cloop_config_yaml, "{claim: sub, value: \"abc123\", role: viewer}")
    error_message = "An unscoped extra mapping must render without empty project/executor keys."
  }
}

# ----------------------------------------------------------- multiple hubs

run "each_hub_gets_both_uris" {
  command = apply

  variables {
    hub_base_urls       = ["https://cloop.example.com", "https://cloop.staging.example.com"]
    extra_redirect_uris = ["http://localhost:8080/auth/callback"]
  }

  assert {
    condition     = length(output.redirect_uris) == 5
    error_message = "Two hubs contribute two URIs each, plus the explicit localhost one."
  }

  assert {
    condition     = contains(output.redirect_uris, "https://cloop.staging.example.com/auth/callback")
    error_message = "Every hub base URL must contribute a callback URI."
  }

  assert {
    condition     = contains(output.redirect_uris, "http://localhost:8080/auth/callback")
    error_message = "extra_redirect_uris must be registered alongside the derived ones."
  }
}

# ---------------------------------------------------------- group claim path

run "group_claims_are_bounded_when_enabled" {
  command = apply

  variables {
    emit_group_claims = true
  }

  # ApplicationGroup counts only groups assigned to this application, which is
  # what keeps a deployment clear of the 200-group cap above which Entra omits
  # the claim entirely and cloop silently falls back to default_role.
  assert {
    condition     = azuread_application.cloop.group_membership_claims == toset(["ApplicationGroup"])
    error_message = "Enabling group claims must default to the bounded ApplicationGroup form."
  }
}

# ------------------------------------------------------------ role assignment

run "assignments_are_keyed_stably" {
  command = apply

  variables {
    role_assignments = {
      admin = { group_object_ids = ["aaaa1111-0000-0000-0000-000000000000"] }
      viewer = {
        group_object_ids = ["bbbb2222-0000-0000-0000-000000000000"]
        user_object_ids  = ["cccc3333-0000-0000-0000-000000000000"]
      }
    }
  }

  assert {
    condition     = length(azuread_app_role_assignment.cloop) == 3
    error_message = "Every (role, principal) pair must become one assignment."
  }

  # Keyed by role and object ID rather than by list position: a for_each keyed
  # on an index destroys and recreates everyone below a removed entry, which
  # here means briefly revoking their access.
  assert {
    condition     = contains(keys(azuread_app_role_assignment.cloop), "admin/group/aaaa1111-0000-0000-0000-000000000000")
    error_message = "Assignment keys must be derived from the role and principal, not from list order."
  }

  assert {
    condition     = azuread_app_role_assignment.cloop["admin/group/aaaa1111-0000-0000-0000-000000000000"].app_role_id == output.app_role_ids["admin"]
    error_message = "An assignment must reference the app role ID of the role it is keyed under."
  }
}

# ----------------------------------------------------------- input validation

run "plaintext_hub_urls_are_refused" {
  command = plan

  variables {
    hub_base_urls = ["http://cloop.example.com"]
  }

  expect_failures = [var.hub_base_urls]
}

run "trailing_slashes_are_refused" {
  command = plan

  variables {
    hub_base_urls = ["https://cloop.example.com/"]
  }

  expect_failures = [var.hub_base_urls]
}

run "localhost_is_allowed_over_plaintext" {
  command = apply

  variables {
    hub_base_urls = ["http://localhost:8080"]
  }

  assert {
    condition     = contains(output.redirect_uris, "http://localhost:8080/auth/callback")
    error_message = "Entra permits plaintext loopback redirect URIs, and a developer running cloop ui locally needs one."
  }
}

run "an_unknown_role_name_is_refused" {
  command = plan

  variables {
    role_assignments = {
      superuser = { user_object_ids = ["dddd4444-0000-0000-0000-000000000000"] }
    }
  }

  expect_failures = [var.role_assignments]
}

# ------------------------------------------------------------ no client secret

run "a_certificate_deployment_creates_no_password" {
  command = apply

  variables {
    client_type          = "confidential"
    create_client_secret = false
  }

  # Supported for a deployment supplying a certificate or a federated identity
  # credential out of band. Both the password and its rotation clock are gated
  # on the same variable, so neither may survive.
  assert {
    condition     = length(azuread_application_password.cloop) == 0
    error_message = "create_client_secret = false must create no client secret."
  }

  assert {
    condition     = length(time_rotating.client_secret) == 0
    error_message = "The rotation clock exists only to date a secret; without one it is a resource that rotates nothing."
  }

  # The outputs must degrade rather than fail: a missing secret is a
  # configuration, not an error, and `terraform output` has to keep working.
  assert {
    condition     = output.client_secret == null
    error_message = "The client_secret output must be null, not an error, when no secret was created."
  }

  assert {
    condition     = output.client_secret_expires_at == null
    error_message = "The expiry output must be null when there is nothing to expire."
  }

  # The rest of the registration is untouched — this is still a working
  # confidential client, just one whose credential arrived another way. Which
  # means the URIs must stay Web-typed: a certificate is a client credential,
  # and Entra will not accept one for a public-client redirect URI.
  assert {
    condition     = strcontains(output.cloop_config_yaml, "enabled: true")
    error_message = "The rendered config must still enable OIDC without a module-managed secret."
  }

  assert {
    condition     = length(azuread_application.cloop.public_client) == 0
    error_message = "A confidential registration must not also expose a public-client platform: the callback would then be redeemable with no credential at all."
  }

  assert {
    condition     = contains(azuread_application.cloop.web[0].redirect_uris, "https://cloop.example.com/auth/callback")
    error_message = "A confidential registration must keep the callback Web-typed, or the certificate it authenticates with cannot be presented."
  }
}

# ------------------------------------------------------- the confidential path

run "confidential_mints_a_secret_and_stays_web_typed" {
  command = apply

  variables {
    client_type = "confidential"
  }

  # client_type alone is enough: create_client_secret defaults to null, which
  # means "follow the client type". An operator who asks for a confidential
  # client should not also have to remember to ask for the credential that
  # choice implies.
  assert {
    condition     = length(azuread_application_password.cloop) == 1
    error_message = "client_type = confidential must mint a client secret without also needing create_client_secret = true."
  }

  assert {
    condition     = length(time_rotating.client_secret) == 1
    error_message = "A secret that exists must have a rotation clock dating it."
  }

  assert {
    condition     = length(azuread_application.cloop.public_client) == 0
    error_message = "A confidential registration must register no public-client platform."
  }

  assert {
    condition     = contains(azuread_application.cloop.web[0].redirect_uris, "https://cloop.example.com/auth/callback")
    error_message = "A confidential registration must register the callback on the Web platform."
  }

  # Here the secret DOES exist, so the rendered config must point at the
  # environment variable that carries it — the inverse of the public case.
  assert {
    condition     = strcontains(output.cloop_config_yaml, "CLOOP_OIDC_CLIENT_SECRET")
    error_message = "A confidential config must say where the secret comes from."
  }

  assert {
    condition     = !strcontains(output.cloop_config_yaml, "client_secret:")
    error_message = "Even with a secret, the rendered YAML must stay committable."
  }

  assert {
    condition     = output.client_type == "confidential"
    error_message = "The client_type output must report what was registered."
  }
}

# A secret on a public client is refused, not silently dropped. Entra will not
# accept a client credential for a code issued to a public-client redirect URI,
# so honouring the request is impossible and ignoring it would leave an
# operator believing the hub authenticates when it does not.
run "a_secret_on_a_public_client_is_refused" {
  command = plan

  variables {
    client_type          = "public"
    create_client_secret = true
  }

  expect_failures = [azuread_application.cloop]
}

# --------------------------------------------------- the rendered YAML is YAML

run "the_rendered_config_parses_as_yaml" {
  command = apply

  variables {
    # Deliberately hostile values. Every scalar in the rendered block goes
    # through jsonencode() — JSON being a subset of YAML, that produces a valid
    # double-quoted scalar — and these are the inputs that would expose it if
    # any did not: a colon-space starts a mapping, a leading `&` is an anchor,
    # a `#` begins a comment, and a `"` closes the scalar early. A project name
    # is operator-supplied, so none of this is hypothetical.
    cloop_admin_emails = ["first.last+cloop@example.com"]
    cloop_extra_role_mappings = [
      { claim = "group", value = "a: b #c", role = "viewer", project = "team \"x\": prod" },
      { claim = "sub", value = "&anchor", role = "operator", executor = "edge-1" },
    ]
  }

  # Parses at all. Without this the suite could only ever assert that certain
  # substrings appear, which is true of a file that no parser accepts.
  assert {
    condition     = can(yamldecode(output.cloop_config_yaml))
    error_message = "The rendered cloop config is not valid YAML."
  }

  # And the values land where cloop reads them, rather than merely appearing
  # somewhere in the document.
  assert {
    condition     = yamldecode(output.cloop_config_yaml).ui.oidc.issuer == output.issuer
    error_message = "ui.oidc.issuer did not survive the round trip."
  }

  assert {
    condition     = yamldecode(output.cloop_config_yaml).ui.oidc.client_id == output.client_id
    error_message = "ui.oidc.client_id did not survive the round trip."
  }

  assert {
    condition     = yamldecode(output.cloop_config_yaml).ui.oidc.redirect_url == output.redirect_url
    error_message = "ui.oidc.redirect_url did not survive the round trip, so it could differ from the registered redirect URI."
  }

  assert {
    condition     = yamldecode(output.cloop_config_yaml).ui.external_url == "https://cloop.example.com"
    error_message = "ui.external_url did not survive the round trip."
  }

  assert {
    condition     = yamldecode(output.cloop_config_yaml).ui.oidc.enabled == true
    error_message = "ui.oidc.enabled must decode as a boolean, not the string \"true\"."
  }

  assert {
    condition     = contains(yamldecode(output.cloop_config_yaml).ui.oidc.scopes, "offline_access")
    error_message = "The scopes list must decode as a list containing offline_access."
  }

  # Four app roles plus the two extras, with the awkward characters intact.
  assert {
    condition     = length(yamldecode(output.cloop_config_yaml).ui.oidc.role_mappings) == 6
    error_message = "Every app-role mapping and every extra mapping must survive as its own list entry."
  }

  # try(), because the decoded list is heterogeneous: an app-role mapping
  # carries {claim, value, role} and nothing else, while a scoped one adds
  # project or executor. A bare m.project is an "Unsupported attribute" error
  # on every object without one — and whether that error is reached depends on
  # whether && short-circuits, which changed between Terraform versions. It
  # short-circuits on 1.15 and does not on 1.9, so the bare form passed here
  # and failed in CI. try() is correct on both and says what is meant: read the
  # key if the mapping has one.
  assert {
    condition = anytrue([
      for m in yamldecode(output.cloop_config_yaml).ui.oidc.role_mappings :
      m.value == "a: b #c" && try(m.project, null) == "team \"x\": prod" && m.role == "viewer"
    ])
    error_message = "A mapping whose value or project contains YAML metacharacters was mangled by the rendering."
  }

  assert {
    condition = anytrue([
      for m in yamldecode(output.cloop_config_yaml).ui.oidc.role_mappings :
      m.value == "&anchor" && try(m.executor, null) == "edge-1"
    ])
    error_message = "A leading & must render as a quoted scalar, not a YAML anchor."
  }

  # The unscoped mappings really do omit the keys, rather than rendering them
  # empty — which is what makes the try() above necessary and is also the
  # behaviour cloop wants: an empty `project` would be a mapping scoped to a
  # project named "".
  assert {
    condition = alltrue([
      for m in yamldecode(output.cloop_config_yaml).ui.oidc.role_mappings :
      try(m.project, null) != "" && try(m.executor, null) != ""
    ])
    error_message = "A mapping rendered an empty project or executor key, which cloop reads as a scope rather than as absent."
  }

  assert {
    condition     = yamldecode(output.cloop_config_yaml).ui.oidc.admin_emails == ["first.last+cloop@example.com"]
    error_message = "admin_emails must decode as a list of strings."
  }
}
