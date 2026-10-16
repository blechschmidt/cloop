# A Key Vault key a cloop hub's KMS plugin wraps the secret store's
# key-encryption keys with, and the hub identity's permission to use it
# (Task 20433).
#
# With secrets.kms configured, each key-encryption key in the hub's database is
# random and stored only as ciphertext the KMS produced. The hub reaches Key
# Vault through the AKS KMS plugin — the one the API server's own encryption at
# rest uses — speaking the Kubernetes KMS v2 protocol over a socket; the plugin
# holds the credential and calls wrapKey and unwrapKey on this key. So what
# opens the store is this key, and the right to call those two operations on
# it: a copy of the database and of CLOOP_SECRET_KEY opens nothing without
# them, every unwrap is in the vault's logs, and removing the role assignment
# below is how the hub's access is taken away.
#
# Three decisions follow from that:
#
#   1. The identity gets "Key Vault Crypto Service Encryption User" — read the
#      key's metadata, wrap, unwrap; no decrypt, no sign, no secrets — scoped
#      to this key, not the vault. It is the role Azure documents for exactly
#      this: a service encrypting its own data keys with a customer key.
#   2. The key's operations are wrapKey and unwrapKey and nothing else, so even
#      a mis-scoped grant cannot make it a signing or encryption key.
#   3. The key is not purge-protected here because that is a property of the
#      vault, which is the caller's. The vault this goes into should have soft
#      delete and purge protection on: a purged key takes every secret the hub
#      sealed with it, and no restore of the database brings them back.

data "azurerm_client_config" "current" {}

locals {
  vault_name = element(split("/", var.key_vault_id), length(split("/", var.key_vault_id)) - 1)
  tenant_id  = coalesce(var.tenant_id, data.azurerm_client_config.current.tenant_id)
}

resource "azurerm_key_vault_key" "kms" {
  name         = var.key_name
  key_vault_id = var.key_vault_id
  key_type     = var.hsm ? "RSA-HSM" : "RSA"
  key_size     = var.key_size

  # Wrap and unwrap: what a KMS plugin calls, and all this key may ever do.
  key_opts = ["wrapKey", "unwrapKey"]

  dynamic "rotation_policy" {
    for_each = var.rotate_after_days > 0 ? [var.rotate_after_days] : []
    content {
      automatic {
        time_after_creation = "P${rotation_policy.value}D"
      }
    }
  }

  tags = var.tags
}

# Azure RBAC: the narrowest grant there is, one data-plane role on one key.
resource "azurerm_role_assignment" "hub" {
  count = var.authorization == "rbac" ? 1 : 0

  scope                = azurerm_key_vault_key.kms.resource_versionless_id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = var.principal_object_id
  principal_type       = var.principal_type
  description          = "cloop hub: wrap and unwrap the secret store's key-encryption keys (secrets.kms)"
}

# A vault on access policies cannot narrow a grant below the vault, so the
# principal gets get, wrapKey and unwrapKey on its keys — still nothing on its
# secrets or certificates, and no decrypt.
resource "azurerm_key_vault_access_policy" "hub" {
  count = var.authorization == "access_policy" ? 1 : 0

  key_vault_id    = var.key_vault_id
  tenant_id       = local.tenant_id
  object_id       = var.principal_object_id
  key_permissions = ["Get", "WrapKey", "UnwrapKey"]
}
