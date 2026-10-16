# Provider requirements for the Key Vault KMS key (Task 20433).
#
# A module of its own, beside the Entra ID application rather than inside it:
# Key Vault is an Azure Resource Manager resource, so it needs azurerm, and a
# module that required azurerm would make every caller of the application
# module configure an azurerm provider — subscription and all — whether or not
# it wants a KMS. Call it next to the application module; see
# ../../examples/complete.
#
# As with the application module, no provider block: the caller configures
# azurerm, with whatever authentication and subscription it uses.

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # Validated against 4.81 and 5.10: azurerm_key_vault_key's
      # resource_versionless_id, the ARM ID the role assignment is scoped to,
      # and its rotation_policy are in both.
      version = ">= 4.0, < 6.0"
    }
  }
}
