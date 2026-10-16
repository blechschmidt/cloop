# Unit tests for the Key Vault KMS key, run with `terraform test` and no Azure
# subscription (Task 20433).
#
# The provider is mocked, so nothing here proves Azure accepts the objects. What
# it proves is what the module claims about itself, and those are security
# claims: that the key can wrap and unwrap and nothing else, that the hub's
# identity is granted exactly the wrap/unwrap role and only on this key, and
# that the plugin is told to listen where the hub dials.
#
#   cd deploy/terraform/azure-entra-id/modules/key-vault-kms && \
#     terraform init -backend=false && terraform test

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id = "11111111-2222-3333-4444-555555555555"
    }
  }

  mock_resource "azurerm_key_vault_key" {
    defaults = {
      version                 = "0123456789abcdef0123456789abcdef"
      versionless_id          = "https://cloop-kv.vault.azure.net/keys/cloop-hub-kms"
      resource_versionless_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/cloop-kv/keys/cloop-hub-kms"
    }
  }
}

variables {
  key_vault_id        = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/cloop-kv"
  principal_object_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}

run "the_key_wraps_and_unwraps_and_nothing_else" {
  command = plan

  assert {
    condition     = toset(azurerm_key_vault_key.kms.key_opts) == toset(["wrapKey", "unwrapKey"])
    error_message = "the key's operations must be wrapKey and unwrapKey alone"
  }
  assert {
    condition     = azurerm_key_vault_key.kms.key_type == "RSA-HSM" && azurerm_key_vault_key.kms.key_size == 3072
    error_message = "the default key must be a 3072-bit HSM-protected RSA key"
  }
  assert {
    condition     = length(azurerm_key_vault_key.kms.rotation_policy) == 0
    error_message = "no rotation policy unless rotate_after_days asks for one"
  }
}

run "rbac_grants_the_wrap_role_on_the_key_alone" {
  command = apply

  assert {
    condition     = length(azurerm_role_assignment.hub) == 1 && length(azurerm_key_vault_access_policy.hub) == 0
    error_message = "rbac must grant one role assignment and no access policy"
  }
  assert {
    condition     = azurerm_role_assignment.hub[0].role_definition_name == "Key Vault Crypto Service Encryption User"
    error_message = "the hub's identity must hold the wrap/unwrap role, nothing broader"
  }
  assert {
    condition     = azurerm_role_assignment.hub[0].scope == azurerm_key_vault_key.kms.resource_versionless_id
    error_message = "the role must be scoped to the key, not the vault"
  }
  assert {
    condition     = azurerm_role_assignment.hub[0].principal_id == var.principal_object_id
    error_message = "the role must be granted to the identity named"
  }
}

run "an_access_policy_grants_wrap_and_unwrap_only" {
  command = apply

  variables {
    authorization = "access_policy"
  }

  assert {
    condition     = length(azurerm_role_assignment.hub) == 0 && length(azurerm_key_vault_access_policy.hub) == 1
    error_message = "access_policy must grant one access policy and no role assignment"
  }
  assert {
    condition     = toset(azurerm_key_vault_access_policy.hub[0].key_permissions) == toset(["Get", "WrapKey", "UnwrapKey"])
    error_message = "the access policy must grant get, wrapKey and unwrapKey on keys and nothing else"
  }
  assert {
    condition     = length(coalesce(azurerm_key_vault_access_policy.hub[0].secret_permissions, [])) == 0
    error_message = "the access policy must grant nothing on secrets"
  }
  assert {
    condition     = azurerm_key_vault_access_policy.hub[0].tenant_id == "11111111-2222-3333-4444-555555555555"
    error_message = "a null tenant_id must take the tenant azurerm is authenticated to"
  }
}

run "a_software_key_and_a_rotation_policy" {
  command = plan

  variables {
    hsm               = false
    key_size          = 4096
    rotate_after_days = 180
  }

  assert {
    condition     = azurerm_key_vault_key.kms.key_type == "RSA" && azurerm_key_vault_key.kms.key_size == 4096
    error_message = "hsm = false must create a software-protected RSA key of the size asked for"
  }
  assert {
    condition     = azurerm_key_vault_key.kms.rotation_policy[0].automatic[0].time_after_creation == "P180D"
    error_message = "rotate_after_days must become the rotation policy's time_after_creation"
  }
}

run "the_plugin_listens_where_the_hub_dials" {
  command = apply

  assert {
    condition     = contains(output.kms_plugin_args, "--listen-addr=unix:///var/run/kmsplugin/socket.sock")
    error_message = "the plugin must listen on the socket the chart shares with the hub"
  }
  assert {
    condition     = contains(output.kms_plugin_args, "--keyvault-name=cloop-kv") && output.key_vault_name == "cloop-kv"
    error_message = "the vault's name must be read off its resource ID"
  }
  assert {
    condition     = contains(output.kms_plugin_args, "--key-version=0123456789abcdef0123456789abcdef")
    error_message = "the plugin must be pinned to the key's current version"
  }
  assert {
    condition     = yamldecode(output.cloop_secrets_yaml).secrets.kms.kmsv2.endpoint == "unix:///var/run/kmsplugin/socket.sock"
    error_message = "the rendered secrets section must dial the plugin's socket"
  }
  assert {
    condition     = yamldecode(output.helm_values_yaml).kms.kmsv2.socketDir == "/var/run/kmsplugin" && yamldecode(output.helm_values_yaml).kms.kmsv2.socketName == "socket.sock"
    error_message = "the rendered chart values must put the socket where the plugin listens"
  }
}

run "refuses_what_azure_would_refuse_later" {
  command = plan

  variables {
    key_vault_id      = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/notavault"
    rotate_after_days = 7
  }

  expect_failures = [
    var.key_vault_id,
    var.rotate_after_days,
  ]
}
