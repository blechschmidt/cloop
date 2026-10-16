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
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0, < 6.0"
    }
  }
}

provider "azuread" {}

# For the Key Vault key below; the sign-in application needs none of it.
provider "azurerm" {
  features {}
}

# The hub's SCIM credential, once the hub is up and has minted one:
#
#   cloop hub scim credential create entra       # on the hub; printed once
#   TF_VAR_cloop_scim_token=cloop_scim_... terraform apply
#
# Unset, the module skips provisioning, so the first apply — before the hub
# exists to mint anything — creates the sign-in application alone.
variable "cloop_scim_token" {
  description = "The SCIM credential `cloop hub scim credential create entra` printed. Null skips provisioning."
  type        = string
  default     = null
  sensitive   = true
}

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

  # Provisioning: everyone in role_assignments is in the job's scope, so
  # disabling, deleting or unassigning any of them in the directory suspends
  # them on the hub at Entra's next cycle. An account kept disabled for 30
  # days is offboarded in full — unless a legal hold keeps its credentials.
  # Conditional, so the second apply — the one with the token — is what turns
  # it on. nonsensitive(): comparing a sensitive value is sensitive too, and
  # the module derives a for_each and its outputs from this object, both of
  # which Terraform refuses to take sensitive. Whether a token was given is
  # no secret.
  scim_provisioning = nonsensitive(var.cloop_scim_token == null) ? null : {
    offboard_after_days = 30
  }
  scim_secret_token = var.cloop_scim_token

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

output "scim_base_address" {
  description = "Where Entra provisions the hub. Null until cloop_scim_token is set."
  value       = module.cloop_sso.scim_base_address
}

output "discovery_url" {
  description = "curl this from the hub before blaming cloop for a failed sign-in."
  value       = module.cloop_sso.discovery_url
}

# The secret store's key-encryption keys held by Key Vault instead of derived
# from CLOOP_SECRET_KEY (Task 20433): an HSM key in a vault the platform team
# already runs — soft delete and purge protection on — and wrap and unwrap on
# that key alone for the identity the hub's KMS plugin sidecar authenticates
# as. A copy of the hub's volume and Secret then opens nothing without this
# key, and removing the role assignment takes the hub's access away.
data "azurerm_key_vault" "platform" {
  name                = "platform-kv"
  resource_group_name = "platform"
}

# The user-assigned identity the hub's Pods run with (the KMS plugin reads its
# client ID from azure.json).
data "azurerm_user_assigned_identity" "cloop_hub" {
  name                = "cloop-hub"
  resource_group_name = "cloop"
}

module "cloop_kms" {
  source = "../../modules/key-vault-kms"

  key_vault_id        = data.azurerm_key_vault.platform.id
  principal_object_id = data.azurerm_user_assigned_identity.cloop_hub.principal_id

  # A new key version yearly. The hub follows it once the plugin is pointed at
  # it: `cloop hub key rewrap`, or the cluster leader within a minute.
  rotate_after_days = 365
}

output "cloop_kms_helm_values" {
  description = "The cloop-hub chart's kms values for the key: pin the plugin image, create the kms-azure-json Secret, and helm upgrade with them."
  value       = module.cloop_kms.helm_values_yaml
}
