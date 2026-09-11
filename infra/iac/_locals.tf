# Giano — name_prefix, default_tags, and every shared derived value other files read by name.
# specs/INFRASTRUCTURE.md §4.3.

locals {
  name_prefix = join("-", [var.project_name, terraform.workspace])

  default_tags = {
    managed_by   = "terraform"
    org_name     = var.org_name
    project_name = var.project_name
    env          = terraform.workspace
    tfstate      = "s3:${var.s3_tfstate_name}"
  }

  # 1Password coordinates for this environment's secrets — §12.2. op_vault_suffix is declared
  # in asm.vars.tf.
  op_vault = "${title(var.project_name)} ${var.op_vault_suffix[terraform.workspace]}"
  op_item  = "secrets-${terraform.workspace}"

  # DNS apex for this environment — §6.1. dns_zone / dns_prefix are declared in dns.vars.tf.
  dns_zone = var.dns_zone[terraform.workspace] # appliedblockchain.dev
  dns_apex = "${var.dns_prefix[terraform.workspace]}.${local.dns_zone}"
  # dev.giano.appliedblockchain.dev

  # Giano's own serving hostnames — never relying parties themselves (§3.4, §6.4).
  hosts = {
    wallet    = "wallet.${local.dns_apex}"
    api       = "api.${local.dns_apex}"
    paymaster = "paymaster.${local.dns_apex}"
  }

  # Per-tenant dApp and wallet hostnames, keyed by tenant slug (§2.1, §6.4, §4.7).
  tenant_hosts = {
    example = {
      dapp   = "example.${local.dns_apex}"
      wallet = "wallet.example.${local.dns_apex}"
    }
    byoui = {
      dapp   = "byoui.${local.dns_apex}"
      wallet = "wallet.byoui.${local.dns_apex}"
    }
  }

  # The application database name — matches the compose reference's POSTGRES_DB default (§8, §7.4).
  app_db_name = "giano"

  # every stock-UI tenant wallet host, plus Giano's own wallet host — ALB rule 40 (§5.7) and
  # the wildcard-exempt SNI certificates (§6.3).
  stock_ui_wallet_hosts = concat([local.hosts.wallet], var.tenant_wallet_hosts[terraform.workspace])

  # --- Delivery. §15.1 -------------------------------------------------
  # The version this environment runs, DECLARED in infra/versions.json and merged to main to
  # deploy. A JSON file rather than a Terraform variable because it has two readers, and the
  # second is the deploy workflow, which must parse it with `jq` and without Terraform — a
  # `.tf` variable would have to be grepped out of HCL.
  #
  # Two writers register task definitions against the same services — `terraform apply` and
  # deploy.yml — and this is what keeps them from disagreeing: both read this one declared
  # value, so each renders an equivalent task definition and an apply converges on whatever
  # deploy.yml already rolled out rather than reverting it (§15.1). NEVER a literal "latest":
  # every ECR repo has IMMUTABLE tags and CI never pushes that tag (§11), so a task definition
  # built from it can never actually pull.
  #
  # lookup() with an empty-string fallback rather than a bare index, so a missing workspace key
  # reaches the task definition's precondition (which names the file to edit) instead of
  # `terraform validate` failing on the `default` workspace with an opaque "key does not
  # identify an element" error.
  image_tag = lookup(jsondecode(file("${path.module}/../versions.json")), terraform.workspace, "")

  # Bump by hand whenever asm.tf's database-url format() string itself changes — a new query
  # param, a different scheme — independent of database-password's own rotation count in
  # 1Password. secret_string_wo is never read back, so combining the two into one
  # secret_string_wo_version (asm.tf) is what makes EITHER a password rotation or a
  # code-only DSN format change actually reach Secrets Manager on the next apply.
  # v2: added ?sslmode=require — RDS's parameter group ships rds.force_ssl = 1 by default and a
  # plaintext connection is rejected outright, not degraded.
  # v3: added &uselibpqcompat=true — sslmode=require alone is an alias for verify-full on
  # recent pg-connection-string, and RDS's cert chains to Amazon's own CA, not Node's trust
  # store, so v2 alone still failed with "self-signed certificate in certificate chain".
  database_url_format_version = 3
}
