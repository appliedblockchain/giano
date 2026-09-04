# Naming, tagging and the derived values more than one file needs. §4.3

locals {
  name_prefix = join("-", [var.project_name, terraform.workspace])

  default_tags = {
    managed_by   = "terraform"
    org_name     = var.org_name
    project_name = var.project_name
    env          = terraform.workspace
    tfstate      = "s3:${var.s3_tfstate_name}"
  }

  # 1Password coordinates for this environment's secrets. §12.2
  #
  # Derived, never typed: selecting a workspace selects the vault, so there is
  # no way to point a dev apply at production's secrets short of editing the
  # map. `prd` is deliberately a vault of its own — who can read a production
  # credential is then a decision made once, in 1Password, rather than a
  # consequence of being on the project.
  op_vault = "${title(var.project_name)} ${var.op_vault_suffix[terraform.workspace]}"
  op_item  = "secrets-${terraform.workspace}"

  # --- DNS. §6.1 ----------------------------------------------------------
  # Two values, not one: DNSimple wants the registrable zone separately from
  # the record name, and a single combined variable has to be split again at
  # every call site — which is where the §6.3 trimsuffix mistakes come from.
  dns_zone = var.dns_zone[terraform.workspace]                          # appliedblockchain.dev
  dns_apex = "${var.dns_prefix[terraform.workspace]}.${local.dns_zone}" # dev.giano.appliedblockchain.dev

  # Giano's own hostnames — infrastructure, shared by every tenant, and never
  # a relying party. §2.1
  hosts = {
    wallet    = "wallet.${local.dns_apex}"
    api       = "api.${local.dns_apex}"
    paymaster = "paymaster.${local.dns_apex}"
  }

  # The two tenants of this environment (D17). Each wallet host is that
  # tenant's WebAuthn RP ID and is irreversible — R1. `example` takes the
  # stock UI and CNAMEs to local.hosts.wallet; `byoui` brings its own SPA and
  # points at Giano's wallet hostname not at all.
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

  # The stock-UI tenant wallet hostnames wallet-web answers on, alongside
  # Giano's own serving hostname. §5.7 rule 40.
  tenant_wallet_hosts = var.tenant_wallet_hosts[terraform.workspace]
  wallet_web_hosts    = concat([local.hosts.wallet], local.tenant_wallet_hosts)

  # Every wallet host that needs a certificate of its own: two labels under
  # the apex, so the wildcard does not cover it. §6.3
  tenant_cert_hosts = toset(concat(
    local.tenant_wallet_hosts,
    var.byo_wallet_enabled[terraform.workspace] ? [local.tenant_hosts.byoui.wallet] : [],
  ))

  # --- Compute ------------------------------------------------------------
  private_subnet_ids = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  public_subnet_ids  = [aws_subnet.subnet-a-pub.id, aws_subnet.subnet-b-pub.id]

  app_db_name = "giano"

  # Service discovery namespace. §9.4
  service_discovery_namespace = "${local.name_prefix}.local"

  # The service roster, for the things that iterate services rather than
  # define them: the Datadog monitors (§17.3.5) and the scheduler (§17.2).
  # `datadog_source` selects Datadog's parsing pipeline — §17.3.4.
  ecs_services = {
    "wallet-api"           = { datadog_source = "nodejs" }
    "wallet-web"           = { datadog_source = "nginx" }
    "custom-example"       = { datadog_source = "nginx" }
    "custom-example-byoui" = { datadog_source = "nginx" }
    "wallet-byo"           = { datadog_source = "nodejs" }
    "paymaster-admin"      = { datadog_source = "nginx" }
    "bundler"              = { datadog_source = "nodejs" }
  }

  # `byoui` costs two tasks that no real deployment pays for (§17.1), so both
  # fall away in a workspace that does not host a BYO tenant.
  enabled_ecs_services = {
    for name, svc in local.ecs_services : name => svc
    if var.byo_wallet_enabled[terraform.workspace] || !contains(["wallet-byo", "custom-example-byoui"], name)
  }
}
