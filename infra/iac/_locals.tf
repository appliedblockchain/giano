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
}
