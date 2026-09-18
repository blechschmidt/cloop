# Inputs.
#
# The required set is deliberately one variable: the hub's external URL. Every
# other Azure-side decision either has a defensible default or is derived, so
# the smallest working call is four lines. Everything that widens the blast
# radius — group claims, admin_emails, a longer-lived secret — is opt-in and
# says why in its description.

variable "hub_base_urls" {
  description = <<-EOT
    External base URLs of the cloop hub(s) this application signs users in to,
    without a trailing slash — e.g. ["https://cloop.example.com"]. The OIDC
    redirect URI is derived by appending the hub's callback path, so this is
    the same value you set as `ui.external_url` in the hub's config.

    More than one entry registers one application for several hubs (staging and
    production, say). That is a real trade-off and not the default for a
    reason: they then share a client secret, an app-role assignment list and a
    consent grant, so anyone who can sign in to staging can sign in to
    production at the same role. Prefer one module instance per hub unless the
    environments genuinely share an audience.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.hub_base_urls) > 0
    error_message = "At least one hub base URL is required."
  }

  validation {
    # Entra rejects a plaintext redirect URI for anything but localhost, and
    # cloop's own config validation rejects a non-TLS issuer the same way.
    # Catching it here costs a plan instead of an apply.
    condition = alltrue([
      for u in var.hub_base_urls :
      startswith(u, "https://") || startswith(u, "http://localhost") || startswith(u, "http://127.0.0.1")
    ])
    error_message = "Hub base URLs must use https:// (http:// is accepted only for localhost/127.0.0.1, which Entra permits for development)."
  }

  validation {
    condition     = alltrue([for u in var.hub_base_urls : !endswith(u, "/")])
    error_message = "Hub base URLs must not end with a trailing slash; the callback path is appended to them."
  }
}

variable "display_name" {
  description = "Display name of the Entra ID application registration, as it appears in the portal and on the consent screen users see."
  type        = string
  default     = "cloop hub"
}

variable "description" {
  description = "Free-text description stored on the application object. Visible to directory admins, not to end users."
  type        = string
  default     = "Single sign-on for the cloop hub (dashboard and HTTP API)."
}

variable "owners" {
  description = <<-EOT
    Object IDs of directory principals who may administer this application.

    Empty (the default) leaves the applying principal as sole owner, which is
    what a service-principal-driven pipeline wants. Naming a human here is what
    keeps the registration manageable after the pipeline's credentials are
    rotated away.
  EOT
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags on the application and service principal objects. Entra tags are plain strings, not key/value pairs."
  type        = list(string)
  default     = ["cloop", "terraform-managed"]
}

variable "extra_redirect_uris" {
  description = <<-EOT
    Additional redirect URIs beyond the ones derived from hub_base_urls.

    Almost always empty. The one case that needs it is a developer running
    `cloop ui` on a laptop against the shared tenant, which wants
    http://localhost:8080/auth/callback registered.

    Every URI here is a place Entra will send an authorization code, so treat
    additions as a change to the trust boundary.
  EOT
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------- credentials

variable "create_client_secret" {
  description = <<-EOT
    Create a client secret for the application.

    cloop is a confidential client: it authenticates to the token endpoint with
    a client secret (client_secret_basic, falling back to client_secret_post)
    in addition to PKCE, so it needs one of these unless you supply a
    certificate or a federated credential out of band. Set this to false only
    if you are doing that.
  EOT
  type        = bool
  default     = true
}

variable "client_secret_rotation_days" {
  description = <<-EOT
    How often the client secret is replaced. The next apply on or after this
    many days since the last rotation mints a new secret.

    Six months by default, which is short on purpose: the secret lands in
    Terraform state and in the hub's environment, and a credential nobody ever
    practises rotating is one whose first rotation happens under an outage.

    Rotation is not automatic — it happens on the next apply *after* the date
    falls due, so the schedule is only as real as how often you run Terraform.
  EOT
  type        = number
  default     = 180

  validation {
    condition     = var.client_secret_rotation_days >= 1 && var.client_secret_rotation_days <= 730
    error_message = "client_secret_rotation_days must be between 1 and 730 (Entra's own maximum secret lifetime is 2 years)."
  }
}

variable "client_secret_grace_days" {
  description = <<-EOT
    How long the secret keeps working past its scheduled rotation date.

    This is the margin for a late apply. With it at zero the secret expires the
    moment rotation falls due, so a pipeline that does not run that day takes
    the hub's sign-in down; the failure is AADSTS7000222 and it looks nothing
    like an expiry. Thirty days is enough to notice and act.

    It is not free: a rotated-out secret stays valid for this long, so treat it
    as the window in which a leaked secret is still useful to an attacker, and
    set it to 0 if you are rotating *because* of a leak.
  EOT
  type        = number
  default     = 30

  validation {
    condition     = var.client_secret_grace_days >= 0 && var.client_secret_grace_days <= 90
    error_message = "client_secret_grace_days must be between 0 and 90."
  }
}

variable "client_secret_rotation_token" {
  description = <<-EOT
    Change this value to mint a new client secret on the next apply, ahead of
    the schedule — the break-glass path for a suspected leak.

    Any string works; a date ("2026-05-14-incident") reads best in a diff. The
    new secret is created and the old one destroyed within a single apply, so
    the hub must be restarted with the new value promptly: there is no overlap
    window on a forced rotation, unlike the scheduled one.
  EOT
  type        = string
  default     = "initial"
}

# ------------------------------------------------------------------- identity

variable "require_app_role_assignment" {
  description = <<-EOT
    Refuse to issue a token to any user who has not been assigned an app role.

    On by default, and it is the single most valuable setting in this module.
    It makes the identity provider deny-by-default in the same direction cloop
    already does with `default_role: none`, so an unassigned employee is
    stopped at Entra rather than signing in successfully and landing on an
    empty dashboard. They see AADSTS50105, which names the application and is
    searchable; the alternative failure mode is a support ticket that says
    "cloop is broken".

    Turning it off is defensible only when every user is meant to reach the
    hub and roles are decided entirely by cloop's own role_mappings.
  EOT
  type        = bool
  default     = true
}

variable "role_assignments" {
  description = <<-EOT
    Which directory principals hold which cloop role, keyed by cloop role name
    (viewer, operator, maintainer, admin).

        role_assignments = {
          admin    = { group_object_ids = [azuread_group.platform.object_id] }
          operator = { group_object_ids = [data.azuread_group.engineering.object_id] }
          viewer   = { user_object_ids  = [data.azuread_user.auditor.object_id] }
        }

    Assigning an app role to a *group* requires Microsoft Entra ID P1 or above.
    User assignment works on every tier — so on a Free tier, populate
    user_object_ids, or leave this empty and bind on the group claim in cloop
    instead (see emit_group_claims).
  EOT
  type = map(object({
    group_object_ids = optional(list(string), [])
    user_object_ids  = optional(list(string), [])
  }))
  default = {}

  validation {
    # The keys are cloop's own role ladder, minus "none" — which exists in
    # cloop as the absence of a grant and has no app role to assign.
    condition = alltrue([
      for role in keys(var.role_assignments) :
      contains(["viewer", "operator", "maintainer", "admin"], role)
    ])
    error_message = "role_assignments keys must be cloop roles: viewer, operator, maintainer, or admin."
  }
}

variable "allow_service_principal_roles" {
  description = <<-EOT
    Also allow application (service principal) identities to hold cloop app
    roles, not just users.

    Off by default. cloop's own scoped API tokens (`cloop token create`) are
    the supported way to give a pipeline non-interactive access, and they are
    auditable inside cloop in a way a directory app-role assignment is not.
    Turn this on only if you specifically want Entra to be the authority for
    machine identities too.
  EOT
  type        = bool
  default     = false
}

# --------------------------------------------------------------- group claims

variable "emit_group_claims" {
  description = <<-EOT
    Emit a `groups` claim in the ID token so cloop can bind roles with
    `claim: group` in addition to (or instead of) app roles.

    Off by default, because on Entra the group claim is a worse instrument than
    it looks:

      * Its values are group *object IDs* — GUIDs — not names, unless the
        group is synced from on-premises AD and you opt into sAMAccountName.
        So the cloop config ends up full of GUIDs.
      * It is capped. A user in more than 200 groups gets no `groups` claim at
        all; Entra substitutes `_claim_names`/`_claim_sources` pointing at
        Microsoft Graph. cloop does not follow that indirection, reads no
        groups, and falls back to `default_role` — a silent demotion that
        strikes exactly the long-tenured people who are in the most groups.

    group_membership_claims defaults to ApplicationGroup, which counts only
    groups assigned to this application and so keeps a normal deployment far
    below the cap. Prefer app roles regardless: they say what the user may do
    here rather than what they are elsewhere.
  EOT
  type        = bool
  default     = false
}

variable "group_membership_claims" {
  description = <<-EOT
    Which groups Entra puts in the claim when emit_group_claims is true.

    ApplicationGroup — only groups assigned to this application. The safe
    choice: it is the one value that bounds the claim, so it cannot trip the
    200-group overage.

    Others: SecurityGroup (security groups and directory roles),
    DirectoryRole, All. Each widens the claim towards the cap.
  EOT
  type        = list(string)
  default     = ["ApplicationGroup"]

  validation {
    condition = length(var.group_membership_claims) > 0 && alltrue([
      for c in var.group_membership_claims :
      contains(["None", "SecurityGroup", "DirectoryRole", "ApplicationGroup", "All"], c)
    ])
    error_message = "group_membership_claims entries must be one of: None, SecurityGroup, DirectoryRole, ApplicationGroup, All."
  }
}

# ------------------------------------------- rendering of the cloop-side block

variable "cloop_default_role" {
  description = <<-EOT
    The `ui.oidc.default_role` written into the rendered cloop config: the role
    an authenticated user gets when they match no mapping.

    "none" — deny by default. Changing it to "viewer" makes everyone your IdP
    will authenticate a reader of every shared project, which is a decision to
    take deliberately rather than inherit.
  EOT
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "viewer", "operator", "maintainer", "admin"], var.cloop_default_role)
    error_message = "cloop_default_role must be one of: none, viewer, operator, maintainer, admin."
  }
}

variable "cloop_admin_emails" {
  description = <<-EOT
    Addresses written into `ui.oidc.admin_emails` in the rendered config.

    Provided as an escape hatch — a break-glass account for the hour before the
    first app-role assignment exists — and not recommended beyond that. Entra's
    own guidance is that `email` is mutable and must not be used for
    authorization; it is also absent for a managed user with no `mail`
    attribute, which turns the entry into a silent no-op. The `admin` app role
    is the durable way to say this.
  EOT
  type        = list(string)
  default     = []
}

variable "cloop_extra_role_mappings" {
  description = <<-EOT
    Extra `ui.oidc.role_mappings` entries appended to the app-role mappings
    this module renders — project- or executor-scoped grants, for instance:

        cloop_extra_role_mappings = [
          { claim = "group", value = "8a1b...", role = "maintainer", project = "payments" },
        ]

    Left empty, the rendered config binds the four app roles and nothing else.
  EOT
  type = list(object({
    claim    = string
    value    = string
    role     = string
    project  = optional(string)
    executor = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for m in var.cloop_extra_role_mappings :
      contains(["group", "role", "email", "sub"], m.claim)
    ])
    error_message = "role mapping claim must be one of: group, role, email, sub."
  }

  validation {
    condition = alltrue([
      for m in var.cloop_extra_role_mappings :
      contains(["none", "viewer", "operator", "maintainer", "admin"], m.role)
    ])
    error_message = "role mapping role must be one of: none, viewer, operator, maintainer, admin."
  }
}
