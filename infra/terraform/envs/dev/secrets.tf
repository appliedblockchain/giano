# SSM parameters (spec §9.1).
#
# SecureString in Parameter Store, not Secrets Manager: standard parameters are free and this
# stack has seven, which Secrets Manager would bill at $0.40 each per month. ECS reads both
# through the execution role identically.
#
# Two kinds of parameter live here.
#
#   GENERATED — Terraform creates the value. It lands in state, which is why the state bucket
#   is private, versioned and encrypted.
#
#   PLACEHOLDER — Terraform creates the parameter with a dummy value and then never looks at it
#   again (`ignore_changes = [value]`). A human writes the real value out of band:
#
#     aws ssm put-parameter --name /giano/dev/rpc-url --type SecureString \
#       --value 'https://base-sepolia.g.alchemy.com/v2/...' --overwrite
#
#   No private key is ever a Terraform variable or a tfvars file. That is how keys reach state,
#   and state reaches a bucket someone can read.

locals {
  ssm_prefix = "/giano/${var.environment}"
}

# ── generated ──────────────────────────────────────────────────────────────────────────────

resource "random_password" "metrics_token" {
  length  = 40
  special = false
}

# GET /metrics requires this bearer token. Nothing scrapes it in dev (D12); a developer curls it.
resource "aws_ssm_parameter" "metrics_token" {
  name  = "${local.ssm_prefix}/metrics-token"
  type  = "SecureString"
  value = random_password.metrics_token.result
}

# The dev tenant's admin key, used by the sponsorship provisioner and by anyone calling the
# admin API. Generated rather than placeholdered because nothing outside this deployment needs
# to know it in advance.
resource "random_password" "tenant_admin_key" {
  length  = 40
  special = false
}

# The same key on its own, so the sponsorship provisioner can be handed a credential rather
# than the whole seed document to parse.
resource "aws_ssm_parameter" "tenant_admin_key" {
  name        = "${local.ssm_prefix}/tenant-admin-key"
  description = "Admin key for the ${var.environment} tenant. Same value as TENANTS_SEED[0].adminKeys[0]."
  type        = "SecureString"
  value       = random_password.tenant_admin_key.result
}

# ── placeholders, written by a human ───────────────────────────────────────────────────────

locals {
  placeholder_parameters = {
    "rpc-url" = "Base Sepolia JSON-RPC endpoint, including the provider API key."

    # Signs ERC-7677 paymaster data. Holds no funds itself; it authorises spending against the
    # paymaster's EntryPoint deposit. `local` is legal here only because this deployment
    # declares GIANO_DEPLOYMENT_CLASS=testnet — loadConfig refuses it under `production`, and
    # the `hsm` alternative needs an adapter the published image does not wire (spec §9.3).
    "sponsorship-signer-key" = "32-byte hex private key that signs paymaster data."

    # Submits bundles and pays L1 gas. Needs Base Sepolia ETH and will drain (spec §6.2).
    "alto-executor-key" = "32-byte hex private key for the Alto executor. Must hold Base Sepolia ETH."
    "alto-utility-key"  = "32-byte hex private key for Alto's utility account."
  }
}

resource "aws_ssm_parameter" "placeholder" {
  for_each = local.placeholder_parameters

  name        = "${local.ssm_prefix}/${each.key}"
  description = each.value
  type        = "SecureString"
  value       = "REPLACE_ME"

  lifecycle {
    # The whole point. Terraform owns the parameter's existence and never its value, so an
    # apply cannot clobber the real secret with the placeholder.
    ignore_changes = [value]
  }
}

# ── the tenant seed ────────────────────────────────────────────────────────────────────────
#
# Composed here rather than placeholdered because every field except the admin key is derived
# from values Terraform already knows, and getting one of them wrong is expensive:
#
#   rpId is IRREVERSIBLE per tenant. Every passkey binds to it. Renaming the wallet host
#   orphans every credential created against it (spec §17 R1).
#
# The admin key is generated, so the whole document does end up in state — acceptable, and the
# alternative (a placeholder the operator hand-assembles) invites a typo in rpId.

resource "aws_ssm_parameter" "tenants_seed" {
  name        = "${local.ssm_prefix}/tenants-seed"
  description = "TENANTS_SEED for wallet-api. Upserted by slug at boot."
  type        = "SecureString"

  value = jsonencode([{
    slug         = var.environment
    walletOrigin = "https://${local.hosts.wallet}"
    rpId         = local.hosts.wallet
    rpName       = var.brand_name
    allowedDappOrigins = [
      "https://${local.hosts.app}",
    ]
    # The thin SDK polls the public receipt endpoint from the dApp origin, cross-origin.
    corsOrigins = [
      "https://${local.hosts.app}",
    ]
    openRegistration = var.open_registration
    adminKeys        = [random_password.tenant_admin_key.result]
  }])
}
