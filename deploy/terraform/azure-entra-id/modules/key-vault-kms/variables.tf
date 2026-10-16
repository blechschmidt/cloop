# Inputs for the Key Vault key a cloop hub wraps its key-encryption keys with.

variable "key_vault_id" {
  description = <<-EOT
    The Azure Resource Manager ID of the Key Vault the key is created in:
    /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>.
    The vault is yours — soft delete and purge protection on, as Azure's own
    guidance for a vault holding encryption keys has it — and this module adds
    one key to it. A purged key takes every secret the hub sealed with it.
  EOT
  type        = string

  validation {
    condition     = can(regex("^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.KeyVault/vaults/[A-Za-z0-9-]{3,24}$", var.key_vault_id))
    error_message = "key_vault_id must be a Key Vault's resource ID: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>."
  }
}

variable "key_name" {
  description = "The key's name in the vault."
  type        = string
  default     = "cloop-hub-kms"

  validation {
    condition     = can(regex("^[0-9A-Za-z-]{1,127}$", var.key_name))
    error_message = "key_name may hold letters, digits and hyphens, at most 127 of them."
  }
}

variable "hsm" {
  description = <<-EOT
    Create an HSM-protected key (RSA-HSM), which needs a Premium vault. False
    creates a software-protected RSA key, which a Standard vault can hold.
  EOT
  type        = bool
  default     = true
}

variable "key_size" {
  description = "RSA modulus size in bits."
  type        = number
  default     = 3072

  validation {
    condition     = contains([2048, 3072, 4096], var.key_size)
    error_message = "key_size must be 2048, 3072 or 4096."
  }
}

variable "principal_object_id" {
  description = <<-EOT
    The object ID of the identity the KMS plugin authenticates to Key Vault
    as — the principal_id of a user-assigned managed identity the hub's Pods
    run with, or a service principal's object ID. It is granted wrap and
    unwrap on this key and nothing else: not on the vault, not on its other
    keys, and never get or decrypt on secrets.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.principal_object_id))
    error_message = "principal_object_id must be an object ID (a GUID)."
  }
}

variable "principal_type" {
  description = "The principal's type, for the role assignment: ServicePrincipal (a managed identity is one), User or Group."
  type        = string
  default     = "ServicePrincipal"

  validation {
    condition     = contains(["ServicePrincipal", "User", "Group"], var.principal_type)
    error_message = "principal_type must be ServicePrincipal, User or Group."
  }
}

variable "authorization" {
  description = <<-EOT
    How the vault authorizes data-plane access: "rbac" (Azure RBAC — the
    principal gets "Key Vault Crypto Service Encryption User" scoped to this
    one key) or "access_policy" (a vault access policy granting get, wrapKey
    and unwrapKey on keys — vault-wide, which access policies cannot narrow).
    RBAC is the narrower of the two and Azure's recommendation.
  EOT
  type        = string
  default     = "rbac"

  validation {
    condition     = contains(["rbac", "access_policy"], var.authorization)
    error_message = "authorization must be rbac or access_policy."
  }
}

variable "tenant_id" {
  description = "The tenant of principal_object_id, for an access policy. Null takes the tenant azurerm is authenticated to."
  type        = string
  default     = null
}

variable "rotate_after_days" {
  description = <<-EOT
    Have Key Vault create a new version of the key this many days after the
    last, through the key's rotation policy. 0 leaves rotation to you. A new
    version reaches the hub when the KMS plugin is pointed at it (the AKS
    plugin takes the version as a flag): the plugin then reports a new key ID,
    the hub's cluster leader rewraps its key-encryption keys onto it within a
    minute, and the old version can be disabled once `cloop hub key list`
    names it on no live key. Never purge a version before then.
  EOT
  type        = number
  default     = 0

  validation {
    condition     = var.rotate_after_days == 0 || (var.rotate_after_days >= 30 && var.rotate_after_days <= 1095)
    error_message = "rotate_after_days must be 0 or between 30 and 1095."
  }
}

variable "plugin_socket" {
  description = "Where the KMS plugin listens, as the hub's secrets.kms.kmsv2.endpoint names it. The Helm chart's default."
  type        = string
  default     = "/var/run/kmsplugin/socket.sock"

  validation {
    condition     = startswith(var.plugin_socket, "/")
    error_message = "plugin_socket must be an absolute path."
  }
}

variable "plugin_image" {
  description = <<-EOT
    The AKS KMS plugin image the rendered Helm values name
    (mcr.microsoft.com/oss/azure/kms/keyvault:<version>, pinned by digest).
    Empty renders a placeholder to replace.
  EOT
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags set on the key."
  type        = map(string)
  default     = {}
}
