# Secrets Manager, fed from the 1Password bundle. §7, §12
#
# 1Password is the source of truth; Secrets Manager is a mirror. The note is
# read TWICE, by two different mechanisms, and that is deliberate:
#
#   data.external      → names and versions only. Results are STORED IN STATE,
#                        which is why it returns no values.
#   ephemeral resource → the values. Never enters state, and can only reach a
#                        write-only argument or an ephemeral variable.
#
# Collapsing them into one read is the mistake that puts every secret in the
# state file. §12.5

data "external" "secret_inventory" {
  # `op item get --vault` rather than `op read "op://…"`: the vault is named
  # `Giano dev/stg`, and a secret reference is parsed on `/`, so the URI form
  # resolves the vault as `Giano dev` and fails. The flag takes the name
  # verbatim. §12.2
  #
  # `set -euo pipefail` matters more than it looks: without it a failed read
  # sends an empty string to jq, jq emits null, and Terraform sees an
  # inventory of zero secrets — which plans as DESTROY EVERY SECRET in the
  # environment. With it, the data source fails and the plan stops.
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    op item get "${local.op_item}" --vault "${local.op_vault}" \
      --account "${var.op_account}" --format json \
      | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
      | jq -c 'map_values(.version | tostring)'
  EOT
  ]
}

ephemeral "onepassword_item" "secrets" {
  vault = local.op_vault # "Giano dev/stg"
  title = local.op_item  # "secrets-dev"
}

locals {
  # { "database-password" = { version = 1 }, "rpc-url" = { version = 1 }, … }
  #
  # The tostring/tonumber round-trip is not decoration: the external
  # provider's contract is a flat map(string) on stdout, so the jq expression
  # flattens {value, version} down to the version as a string. That flattening
  # is also what makes this safe — see the header.
  secret_inventory = {
    for name, version in data.external.secret_inventory.result :
    name => { version = tonumber(version) }
  }

  # Implicitly ephemeral — derived from an ephemeral resource, so it cannot be
  # persisted or output by accident.
  secret_bundle = jsondecode(ephemeral.onepassword_item.secrets.note_value)
  secret_values = { for k, v in local.secret_bundle : k => v.value }
}

module "asm-app" {
  source = "./modules/aws/asm"

  name_prefix             = local.name_prefix
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  secrets = local.secret_inventory # static, from data.external (§12.4)
  values  = local.secret_values    # ephemeral, from the 1Password note

  additional_tags = { component = "app" }
}

# --- The derived secrets. §7.4 --------------------------------------------
#
# Neither is in the 1Password note, so neither is in the static inventory —
# which is why both are their own resources rather than entries in the
# module's for_each.

# wallet-api consumes a full DSN, not a password.
resource "aws_secretsmanager_secret" "database-url" {
  name                    = "${local.name_prefix}-database-url"
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-database-url" }
}

resource "aws_secretsmanager_secret_version" "database-url" {
  secret_id = aws_secretsmanager_secret.database-url.id

  # derived from an ephemeral value, so implicitly ephemeral itself.
  #
  # urlencode on the password is not optional: a #, / or @ in a DSN password
  # silently truncates the connection string, and the failure looks like a
  # wrong hostname.
  secret_string_wo = format(
    "postgres://%s:%s@%s:%d/%s",
    var.app-db-username[terraform.workspace],
    urlencode(local.secret_values["database-password"]),
    module.app-db.address,
    module.app-db.port,
    local.app_db_name,
  )

  # Rotates with the password it embeds: bumping the password's version in
  # 1Password moves both the database and the DSN in one apply.
  secret_string_wo_version = local.secret_inventory["database-password"].version
}

# The Datadog API key. A provider credential AND a container secret — the one
# value that crosses the §4.6.1 boundary. It stays in the shared DevOps item
# (one value, one home) and Terraform mirrors it here, because the Agent
# sidecar and FireLens both resolve it from Secrets Manager at runtime.
resource "aws_secretsmanager_secret" "datadog-api-key" {
  name                    = "${local.name_prefix}-datadog-api-key"
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-datadog-api-key" }
}

resource "aws_secretsmanager_secret_version" "datadog-api-key" {
  secret_id        = aws_secretsmanager_secret.datadog-api-key.id
  secret_string_wo = local.datadog_api_key # ephemeral, from the DevOps item

  # A plain variable rather than a version carried next to the value: the
  # DevOps item is a shell fragment shared with other projects and has nowhere
  # to put one. IF THAT KEY IS ROTATED, BUMP THIS — otherwise Secrets Manager
  # keeps the old one and every task quietly stops reporting. R24
  secret_string_wo_version = var.datadog_api_key_version
}
