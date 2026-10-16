# What a hub and its KMS plugin need to use the key.

locals {
  key_version = azurerm_key_vault_key.kms.version

  # The AKS KMS plugin's own flags. It listens where the hub dials, finds the
  # key by vault, name and version, and reads its credential from azure.json
  # (a managed identity's client ID, or a service principal) at the path the
  # chart's kms.plugin.volumeMounts put it.
  plugin_args = [
    "--listen-addr=unix://${var.plugin_socket}",
    "--keyvault-name=${local.vault_name}",
    "--key-name=${azurerm_key_vault_key.kms.name}",
    "--key-version=${local.key_version}",
    "--config-file-path=/etc/kubernetes/azure.json",
    "--healthz-port=8787",
  ]

  # The secrets section of a hub's config.yaml outside Helm: the plugin as a
  # sidecar or a host service on the same socket.
  cloop_secrets_yaml = yamlencode({
    secrets = {
      kms = {
        provider = "kmsv2"
        name     = "azure-key-vault:${local.vault_name}/${azurerm_key_vault_key.kms.name}"
        kmsv2 = {
          endpoint = "unix://${var.plugin_socket}"
        }
      }
    }
  })

  # The chart's kms values. The plugin image is left to pin; azure.json is a
  # Secret the caller creates (kubectl create secret generic kms-azure-json
  # --from-file=azure.json).
  helm_values_yaml = yamlencode({
    kms = {
      enabled  = true
      provider = "kmsv2"
      name     = "azure-key-vault:${local.vault_name}/${azurerm_key_vault_key.kms.name}"
      kmsv2 = {
        socketDir  = dirname(var.plugin_socket)
        socketName = basename(var.plugin_socket)
      }
      plugin = {
        image        = var.plugin_image != "" ? var.plugin_image : "mcr.microsoft.com/oss/azure/kms/keyvault:<pin a version by digest>"
        args         = local.plugin_args
        volumeMounts = [{ name = "azure-config", mountPath = "/etc/kubernetes", readOnly = true }]
        volumes      = [{ name = "azure-config", secret = { secretName = "kms-azure-json" } }]
      }
    }
  })
}

output "key_id" {
  description = "The key's versionless URI. Grants and logs name the key by it."
  value       = azurerm_key_vault_key.kms.versionless_id
}

output "key_name" {
  description = "The key's name in the vault."
  value       = azurerm_key_vault_key.kms.name
}

output "key_version" {
  description = "The key's current version: what the AKS KMS plugin is told to use (--key-version)."
  value       = local.key_version
}

output "key_resource_id" {
  description = "The key's versionless Azure Resource Manager ID: the scope of the role assignment."
  value       = azurerm_key_vault_key.kms.resource_versionless_id
}

output "key_vault_name" {
  description = "The vault's name, as the plugin's --keyvault-name takes it."
  value       = local.vault_name
}

output "kms_plugin_args" {
  description = "The AKS KMS plugin's arguments for this key, listening where the hub dials."
  value       = local.plugin_args
}

output "cloop_secrets_yaml" {
  description = "The secrets section of the hub's config.yaml for this key, when the hub is not installed with the Helm chart."
  value       = local.cloop_secrets_yaml
}

output "helm_values_yaml" {
  description = "The cloop-hub chart's kms values for this key. Pin the plugin image before using them."
  value       = local.helm_values_yaml
}
