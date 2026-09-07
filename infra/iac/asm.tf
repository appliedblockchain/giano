<<<<<<< HEAD
# §7, §12 — 1Password is the source of truth for every secret value; Secrets Manager is a
# mirror. Two independent reads of the SAME note: `data.external` for names + rotation
# versions (static, safe to store in state), and an `ephemeral` resource for values (never
# stored anywhere). for_each downstream MUST iterate the former, never the latter.

# ── The secret inventory — names and versions only, §12.4 ──────────────────────────────────
data "external" "secret_inventory" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
=======
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

    # No `op signin` here, deliberately. The 1Password app only grants CLI
    # authorisation to a call it can attribute to an authorised terminal app;
    # a Terraform-parented `op` never gets one, so a signin at this point is
    # auto-dismissed rather than prompting. The grant has to be acquired in
    # the shell first — `op signin --account … && terraform plan` — after
    # which this call reuses it and never prompts. In CI,
    # OP_SERVICE_ACCOUNT_TOKEN removes the app from the path entirely
    # (§12.2, R20).
>>>>>>> main
    op item get "${local.op_item}" --vault "${local.op_vault}" \
      --account "${var.op_account}" --format json \
      | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
      | jq -c 'map_values(.version | tostring)'
  EOT
  ]
}

<<<<<<< HEAD
locals {
  # { "database-password" = { version = 1 }, "rpc-url" = { version = 1 }, … }
  secret_inventory = {
    for name, version in data.external.secret_inventory.result :
    name => { version = tonumber(version) }
  }
}

# ── The values — ephemeral, never touch state, §12.5 ───────────────────────────────────────
=======
# The vault UUID, not its name — see the note in _init.tf. The `op item get`
# call above takes the name instead, because the CLI resolves either.
>>>>>>> main
data "onepassword_vault" "secrets" {
  name = local.op_vault # "Giano dev/stg"
}

ephemeral "onepassword_item" "secrets" {
  vault = data.onepassword_vault.secrets.uuid # UUID, not name — §4.6.1
  title = local.op_item                       # "secrets-dev"
}

locals {
<<<<<<< HEAD
  # implicitly ephemeral — derived from an ephemeral resource
=======
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
>>>>>>> main
  secret_bundle = jsondecode(ephemeral.onepassword_item.secrets.note_value)
  secret_values = { for k, v in local.secret_bundle : k => v.value }
}

<<<<<<< HEAD
# ── The mirror — §7.2, §7.3 ─────────────────────────────────────────────────────────────────
=======
>>>>>>> main
module "asm-app" {
  source = "./modules/aws/asm"

  name_prefix             = local.name_prefix
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  secrets = local.secret_inventory # static, from data.external (§12.4)
  values  = local.secret_values    # ephemeral, from the 1Password note
<<<<<<< HEAD
}

# ── The derived secrets — §7.4 ──────────────────────────────────────────────────────────────

# database-url: composed by Terraform from the ephemeral password and the RDS endpoint. NOT
# in the 1Password note — wallet-api consumes a full DSN, not a bare password.
=======

  additional_tags = { component = "app" }
}

# --- The derived secrets. §7.4 --------------------------------------------
#
# Neither is in the 1Password note, so neither is in the static inventory —
# which is why both are their own resources rather than entries in the
# module's for_each.

# wallet-api consumes a full DSN, not a password.
>>>>>>> main
resource "aws_secretsmanager_secret" "database-url" {
  name                    = "${local.name_prefix}-database-url"
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-database-url" }
}

resource "aws_secretsmanager_secret_version" "database-url" {
  secret_id = aws_secretsmanager_secret.database-url.id

<<<<<<< HEAD
  # derived from an ephemeral value, so implicitly ephemeral itself. urlencode() on the
  # password is not optional: a #, / or @ silently truncates the DSN.
  secret_string_wo = format(
    "postgres://%s:%s@%s:%d/%s",
    var.db_username[terraform.workspace],
=======
  # derived from an ephemeral value, so implicitly ephemeral itself.
  #
  # urlencode on the password is not optional: a #, / or @ in a DSN password
  # silently truncates the connection string, and the failure looks like a
  # wrong hostname.
  secret_string_wo = format(
    "postgres://%s:%s@%s:%d/%s",
    var.app-db-username[terraform.workspace],
>>>>>>> main
    urlencode(local.secret_values["database-password"]),
    module.app-db.address,
    module.app-db.port,
    local.app_db_name,
  )

<<<<<<< HEAD
  # rotates with the password it embeds
  secret_string_wo_version = local.secret_inventory["database-password"].version
}

# datadog-api-key: mirrored OUT of the shared DevOps vault — the Agent sidecar and FireLens
# both resolve it from Secrets Manager at runtime. Never mirrored: the APP key — no container
# uses it.
=======
  # Rotates with the password it embeds: bumping the password's version in
  # 1Password moves both the database and the DSN in one apply.
  secret_string_wo_version = local.secret_inventory["database-password"].version
}

# The Datadog API key. A provider credential AND a container secret — the one
# value that crosses the §4.6.1 boundary. It stays in the shared DevOps item
# (one value, one home) and Terraform mirrors it here, because the Agent
# sidecar and FireLens both resolve it from Secrets Manager at runtime.
>>>>>>> main
resource "aws_secretsmanager_secret" "datadog-api-key" {
  name                    = "${local.name_prefix}-datadog-api-key"
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-datadog-api-key" }
}

resource "aws_secretsmanager_secret_version" "datadog-api-key" {
<<<<<<< HEAD
  secret_id = aws_secretsmanager_secret.datadog-api-key.id
  # ephemeral — from the DevOps item (_init.tf)
  secret_string_wo         = local.datadog_api_key
  secret_string_wo_version = var.datadog_api_key_version # plain number, bumped by hand — R24
=======
  secret_id        = aws_secretsmanager_secret.datadog-api-key.id
  secret_string_wo = local.datadog_api_key # ephemeral, from the DevOps item

  # A plain variable rather than a version carried next to the value: the
  # DevOps item is a shell fragment shared with other projects and has nowhere
  # to put one. IF THAT KEY IS ROTATED, BUMP THIS — otherwise Secrets Manager
  # keeps the old one and every task quietly stops reporting. R24
  secret_string_wo_version = var.datadog_api_key_version
>>>>>>> main
}
