# Key Vault key for a cloop hub's sealing keys

Creates the Key Vault key that a cloop hub's KMS plugin wraps the secret
store's key-encryption keys with (`secrets.kms`), and grants the hub's identity
wrap and unwrap on that key alone. See
[the parent module's README](../../README.md#key-vault-for-the-sealing-keys-moduleskey-vault-kms)
for what it creates and why, and the
[runbook](../../../../../docs/operations/runbook.md#keys-in-a-kms) for moving a
hub onto it.

| Input | Default | |
| --- | --- | --- |
| `key_vault_id` | none | **Required.** The vault's ARM ID. Turn on soft delete and purge protection |
| `principal_object_id` | none | **Required.** The identity the KMS plugin authenticates as |
| `principal_type` | `ServicePrincipal` | Also right for a managed identity |
| `authorization` | `rbac` | `access_policy` for a vault that uses access policies |
| `key_name` | `cloop-hub-kms` | |
| `hsm` | `true` | `RSA-HSM` (Premium vault). `false` for `RSA` |
| `key_size` | `3072` | 2048, 3072 or 4096 |
| `rotate_after_days` | `0` | A rotation policy. The hub rewraps once the plugin points at the new version |
| `tenant_id` | the provider's | For an access policy |
| `plugin_socket` | `/var/run/kmsplugin/socket.sock` | Where the plugin listens and the hub connects |
| `plugin_image` | `""` | The AKS KMS plugin image for the rendered Helm values, pinned by digest |
| `tags` | `{}` | |

```bash
terraform init -backend=false && terraform test    # mocked provider; no subscription
```
