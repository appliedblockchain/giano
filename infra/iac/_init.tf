# Giano — terraform block, providers, and every ephemeral read a provider needs to authenticate.
# One root module, environments selected by workspace — specs/INFRASTRUCTURE.md §4.1, §4.5, §4.6.1.

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws         = { source = "hashicorp/aws", version = "~> 6.0" }
    datadog     = { source = "DataDog/datadog", version = "~> 3.60" }
    dnsimple    = { source = "dnsimple/dnsimple", version = "~> 1.9" }
    external    = { source = "hashicorp/external", version = "~> 2.3" }
    onepassword = { source = "1Password/onepassword", version = "~> 3.1" }
    random      = { source = "hashicorp/random", version = "~> 3.6" }
  }

  # Fully specified — there are no -backend-config flags to remember. Workspaces derive the
  # per-environment state key from workspace_key_prefix — §4.5.
  backend "s3" {
    bucket               = "giano-tfstate"
    key                  = "terraform.tfstate"
    workspace_key_prefix = "env"
    region               = "eu-west-2"
    encrypt              = true
    use_lockfile         = true
  }
}

provider "aws" {
  region  = var.aws_region[terraform.workspace]
  profile = var.profile[terraform.workspace]

  default_tags { tags = local.default_tags }
}

# Shared data sources — §4.2
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# ── 1Password — the root of every credential in this deployment (§4.6.1) ──────────────────
provider "onepassword" {
  account = var.op_account # CI overrides with OP_SERVICE_ACCOUNT_TOKEN instead (§12.2)
}

# ── DNSimple provider credentials — shared `DevOps` vault, `dnsimple-terraform` item (§6.2) ─
# ephemeral.vault takes the vault UUID, NOT its name (§4.6.1).
data "onepassword_vault" "devops" {
  name = var.op_devops_vault # "DevOps"
}

ephemeral "onepassword_item" "dnsimple" {
  vault = data.onepassword_vault.devops.uuid
  title = "dnsimple-terraform"
}

locals {
  # implicitly ephemeral — derived from an ephemeral resource.
  # \\s* on BOTH sides of the delimiter: the note has been seen written as
  # `export DNSIMPLE_TOKEN ="..."`, and a space before `=` must not break the plan (R23).
  dnsimple_token = regex(
    "DNSIMPLE_TOKEN\\s*[=:]\\s*['\"]?([^'\"\\s]+)",
    ephemeral.onepassword_item.dnsimple.note_value,
  )[0]
}

provider "dnsimple" {
  token   = local.dnsimple_token
  account = var.dnsimple_account # numeric, from dns.vars.tf — NOT from the note (§6.2)
}

# ── Datadog provider credentials — shared `DevOps` vault, `datadog-terraform` item (§17.3.2) ─
ephemeral "onepassword_item" "datadog" {
  vault = data.onepassword_vault.devops.uuid
  title = "datadog-terraform"
}

locals {
  _datadog_note   = ephemeral.onepassword_item.datadog.note_value
  datadog_api_key = regex("DD_API_KEY[=:]\\s*['\"]?([^'\"\\s]+)", local._datadog_note)[0]
  datadog_app_key = regex("DD_APP_KEY[=:]\\s*['\"]?([^'\"\\s]+)", local._datadog_note)[0]
}

provider "datadog" {
  api_key  = local.datadog_api_key # ephemeral — never in state
  app_key  = local.datadog_app_key
  api_url  = "https://api.${var.datadog_site}"
  validate = var.datadog_enabled[terraform.workspace]
}
