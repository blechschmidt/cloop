# A deployment shaped like a real one: existing directory groups mapped onto
# cloop's role ladder, a production and a staging hub, one project-scoped grant
# that Entra cannot express, and a break-glass admin for the first hour.
#
#   terraform init && terraform apply
#   terraform output -raw cloop_config_yaml
#
# Assigning an app role to a GROUP requires Microsoft Entra ID P1 or above. On
# the Free tier the azuread_app_role_assignment resources below fail at apply
# with "Insufficient privileges"; move those object IDs to user_object_ids, or
# turn on emit_group_claims and bind on the group claim in cloop instead.

terraform {
  required_version = ">= 1.5"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0, < 4.0"
    }
  }
}

provider "azuread" {}

# Groups that already exist in the directory. Read, not created: who belongs to
# "Platform Engineering" is an HR-adjacent decision that does not belong in the
# state file of a dashboard's SSO configuration.
data "azuread_group" "platform" {
  display_name     = "Platform Engineering"
  security_enabled = true
}

data "azuread_group" "engineering" {
  display_name     = "Engineering"
  security_enabled = true
}

data "azuread_group" "security_audit" {
  display_name     = "Security Audit"
  security_enabled = true
}

data "azuread_user" "payments_lead" {
  user_principal_name = "dana@example.com"
}

module "cloop_sso" {
  source = "../.."

  display_name = "cloop hub (production)"

  # One registration for two hubs. Worth being deliberate about: they share a
  # client secret and an assignment list, so anyone who can sign in to staging
  # signs in to production at the same role. Acceptable when staging is staffed
  # by the same people; not acceptable when it is not.
  hub_base_urls = [
    "https://cloop.example.com",
    "https://cloop.staging.example.com",
  ]

  # Someone should still own this after the pipeline's credentials rotate.
  owners = [data.azuread_user.payments_lead.object_id]

  # Entra decides who may sign in at all; cloop decides what they may do.
  # Both deny by default.
  require_app_role_assignment = true
  cloop_default_role          = "none"

  role_assignments = {
    admin      = { group_object_ids = [data.azuread_group.platform.object_id] }
    operator   = { group_object_ids = [data.azuread_group.engineering.object_id] }
    viewer     = { group_object_ids = [data.azuread_group.security_audit.object_id] }
    maintainer = { user_object_ids = [data.azuread_user.payments_lead.object_id] }
  }

  # A grant Entra cannot express: an app role is tenant-wide, but cloop scopes
  # a binding to one project. Dana is a maintainer everywhere by app role
  # above; this narrows nothing — it is here to show the shape. A more typical
  # use is granting one team maintainer on one project without granting it
  # anywhere else, in which case they hold no app role at all and reach the hub
  # through a group claim (emit_group_claims = true).
  cloop_extra_role_mappings = [
    {
      claim   = "role"
      value   = "operator"
      role    = "maintainer"
      project = "payments"
    },
  ]

  # Break-glass, and meant to be removed. It gets someone in before the first
  # app role assignment has replicated; after that the `admin` role is the
  # durable answer, and Entra's own guidance is that `email` is mutable and
  # must not be authorized on.
  cloop_admin_emails = ["break-glass@example.com"]

  # Rotate twice a year, with a month of slack for a late pipeline run.
  client_secret_rotation_days = 180
  client_secret_grace_days    = 30

  tags = ["cloop", "terraform-managed", "production"]
}

output "cloop_config_yaml" {
  value = module.cloop_sso.cloop_config_yaml
}

output "client_secret" {
  value     = module.cloop_sso.client_secret
  sensitive = true
}

output "client_secret_expires_at" {
  description = "Put this in a calendar. An expired secret fails every new sign-in with AADSTS7000222 while existing sessions keep working, so the outage arrives gradually and looks like something else."
  value       = module.cloop_sso.client_secret_expires_at
}

output "service_principal_object_id" {
  description = "Attach Conditional Access policies here — require MFA, or restrict to compliant devices, for cloop specifically."
  value       = module.cloop_sso.service_principal_object_id
}

output "discovery_url" {
  description = "curl this from the hub before blaming cloop for a failed sign-in."
  value       = module.cloop_sso.discovery_url
}
