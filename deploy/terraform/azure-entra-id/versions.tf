# Provider requirements for the cloop Entra ID application module.
#
# Only azuread is required. No `random` provider: the app role IDs are derived
# with uuidv5() from the role names themselves (see main.tf), which keeps them
# stable without a state-stored value and identical across every tenant that
# applies this module — a deleted-and-recreated role ID silently drops every
# assignment made against it, so "stable" is a correctness property here, not
# a tidiness one.
#
# The module deliberately declares no `provider` block. A module that
# configures its own provider cannot be used with an aliased one, cannot be
# used with `for_each`, and hard-codes the caller's authentication. The caller
# configures azuread; see examples/.

terraform {
  required_version = ">= 1.5"

  required_providers {
    azuread = {
      source = "hashicorp/azuread"
      # 3.x renamed `application_id` to `client_id` on
      # azuread_service_principal and changed azuread_application_password to
      # take the application's *resource* ID. Both are used below, so 2.x
      # cannot be supported by the same source.
      #
      # Developed and validated against 3.9.0.
      version = ">= 3.0, < 4.0"
    }

    # Only for the client secret's rotation schedule. azuread deprecated
    # `end_date_relative` in favour of an absolute `end_date`, and an absolute
    # date computed from timestamp() would differ on every plan — a permanent
    # diff that rotates the credential each time anyone runs Terraform.
    # time_rotating holds one date still until it is due.
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9, < 1.0"
    }
  }
}
