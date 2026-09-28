# §7, §12 — 1Password is the source of truth for every secret value; Secrets Manager is a
# mirror. Two independent reads of the SAME note: `data.external` for names + rotation
# versions (static, safe to store in state), and an `ephemeral` resource for values (never
# stored anywhere). for_each downstream MUST iterate the former, never the latter.

# ── The secret inventory — names and versions only, §12.4 ──────────────────────────────────
data "external" "secret_inventory" {
  program = ["bash", "-c", <<-EOT
    set -euo pipefail
    op item get "${local.op_item}" --vault "${local.op_vault}" \
      --account "${var.op_account}" --format json \
      | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
      | jq -c 'map_values(.version | tostring)'
  EOT
  ]
}

locals {
  # { "database-password" = { version = 1 }, "rpc-url-base-sepolia" = { version = 1 }, … }
  secret_inventory = {
    for name, version in data.external.secret_inventory.result :
    name => { version = tonumber(version) }
  }
}

# ── The values — ephemeral, never touch state, §12.5 ───────────────────────────────────────
data "onepassword_vault" "secrets" {
  name = local.op_vault # "Giano dev/stg"
}

ephemeral "onepassword_item" "secrets" {
  vault = data.onepassword_vault.secrets.uuid # UUID, not name — §4.6.1
  title = local.op_item                       # "secrets-dev"
}

locals {
  # implicitly ephemeral — derived from an ephemeral resource
  secret_bundle = jsondecode(ephemeral.onepassword_item.secrets.note_value)
  secret_values = { for k, v in local.secret_bundle : k => v.value }
}

# ── The mirror — §7.2, §7.3 ─────────────────────────────────────────────────────────────────
module "asm-app" {
  source = "./modules/aws/asm"

  name_prefix             = local.name_prefix
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  secrets = local.secret_inventory # static, from data.external (§12.4)
  values  = local.secret_values    # ephemeral, from the 1Password note
}

# ── The derived secrets — §7.4 ──────────────────────────────────────────────────────────────

# database-url: composed by Terraform from the ephemeral password and the RDS endpoint. NOT
# in the 1Password note — wallet-api consumes a full DSN, not a bare password.
resource "aws_secretsmanager_secret" "database-url" {
  name                    = "${local.name_prefix}-database-url"
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-database-url" }
}

resource "aws_secretsmanager_secret_version" "database-url" {
  secret_id = aws_secretsmanager_secret.database-url.id

  # derived from an ephemeral value, so implicitly ephemeral itself. urlencode() on the
  # password is not optional: a #, / or @ silently truncates the DSN.
  #
  # sslmode=require is not optional either: rds.force_ssl = 1 is the system default on this
  # parameter group's family (not something this module's parameter_group block set — it was
  # never disabled), so RDS rejects a plaintext connection outright with "no pg_hba.conf entry
  # ... no encryption". A DSN without it fails at the driver's first connection, every time.
  #
  # uselibpqcompat=true is also required: recent pg-connection-string versions treat plain
  # sslmode=require as an ALIAS for verify-full — full CA-chain validation — and RDS's
  # certificate chains to Amazon's own RDS CA, which is not in Node's default trust store, so
  # the connection fails with "self-signed certificate in certificate chain" instead of
  # connecting. uselibpqcompat restores classic libpq semantics, where require means encrypt
  # only. Accepted here because the instance is already private-subnet and security-group
  # isolated (§5.6) — the connection is encrypted, just not chain-verified.
  secret_string_wo = format(
    "postgres://%s:%s@%s:%d/%s?sslmode=require&uselibpqcompat=true",
    var.db_username[terraform.workspace],
    urlencode(local.secret_values["database-password"]),
    module.app-db.address,
    module.app-db.port,
    local.app_db_name,
  )

  # Rotates with the password it embeds — AND with the DSN's own format. secret_string_wo is
  # never read back, so a version bump is the ONLY signal Terraform has that the value changed;
  # tying this purely to the password's 1Password version would mean a code-only change to the
  # format() string (like adding ?sslmode=require just now) never reaches Secrets Manager at
  # all, because the version number wouldn't move. Combined so either trigger works.
  secret_string_wo_version = local.secret_inventory["database-password"].version * 100 + local.database_url_format_version
}

# datadog-api-key: mirrored OUT of the shared DevOps vault — the Agent sidecar and FireLens
# both resolve it from Secrets Manager at runtime. Never mirrored: the APP key — no container
# uses it.
resource "aws_secretsmanager_secret" "datadog-api-key" {
  name                    = "${local.name_prefix}-datadog-api-key"
  kms_key_id              = aws_kms_key.asm-kms-key.key_id
  recovery_window_in_days = var.asm_recovery_window_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-datadog-api-key" }
}

resource "aws_secretsmanager_secret_version" "datadog-api-key" {
  secret_id = aws_secretsmanager_secret.datadog-api-key.id
  # ephemeral — from the DevOps item (_init.tf)
  secret_string_wo         = local.datadog_api_key
  secret_string_wo_version = var.datadog_api_key_version # plain number, bumped by hand — R24
}
