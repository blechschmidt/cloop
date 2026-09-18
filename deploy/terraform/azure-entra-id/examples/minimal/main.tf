# The smallest call that produces a working sign-in.
#
#   az login --tenant <tenant-id>
#   terraform init && terraform apply
#   terraform output -raw cloop_config_yaml >> /srv/cloop/.cloop/config.yaml
#   export CLOOP_OIDC_CLIENT_SECRET=$(terraform output -raw client_secret)
#
# Nobody can sign in yet, and that is the intended state: the service principal
# requires an app role assignment, and no assignment exists. Grant yourself one
# — through the portal, or by moving to the complete example — and the same
# hub starts letting you in. This ordering is deliberate. A hub that is
# reachable before anyone is authorised is a hub that was briefly open.

terraform {
  required_version = ">= 1.5"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0, < 4.0"
    }
  }
}

provider "azuread" {
  # Tenant comes from the environment: ARM_TENANT_ID, or whatever `az login`
  # selected. Pinning it here would make the example wrong for everyone else.
}

module "cloop_sso" {
  source = "../.."

  hub_base_urls = ["https://cloop.example.com"]
}

output "cloop_config_yaml" {
  description = "Merge into the hub's .cloop/config.yaml."
  value       = module.cloop_sso.cloop_config_yaml
}

output "client_secret" {
  description = "Export as CLOOP_OIDC_CLIENT_SECRET on the hub."
  value       = module.cloop_sso.client_secret
  sensitive   = true
}

output "admin_consent_url" {
  description = "Visit once as a Privileged Role Administrator to consent for the whole tenant."
  value       = module.cloop_sso.admin_consent_url
}
