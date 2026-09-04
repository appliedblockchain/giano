# Terraform settings, providers and the shared data sources. §4.5, §4.6.1

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

  # Fully specified — there are no -backend-config flags to remember. The
  # per-environment key is derived from workspace_key_prefix and the selected
  # workspace: env/dev/terraform.tfstate, env/stg/…, env/prd/…
  backend "s3" {
    bucket               = "gianotest-tfstate"
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

# The root of every credential in this deployment. §12.2
#
# The account is a variable, so the operator's shell needs nothing set — CI
# overrides with OP_SERVICE_ACCOUNT_TOKEN instead, the one case where an
# environment variable is unavoidable. Never both: the provider picks one and
# the failure mode when both are present is a confusing auth error.
provider "onepassword" {
  account = var.op_account
}

# ---------------------------------------------------------------------------
# Provider credentials. §4.6.1
#
# Both items are org infrastructure in the shared DevOps vault, shared with
# other projects. Their notes are shell fragments that `export` the values;
# Terraform reads and parses them rather than requiring them to be sourced
# first, which is what keeps `terraform plan` runnable with nothing run
# beforehand. Neither is Giano's secrets bundle (§12.3).
# ---------------------------------------------------------------------------

# `ephemeral "onepassword_item"` takes the vault's UUID, not its name — the
# provider's schema says so, and passing a name does not fail cleanly: the
# provider resolves it, returns the UUID, and Terraform rejects the result
# because an ephemeral resource's returned attributes must match its
# configuration exactly:
#
#   Error: Provider produced invalid ephemeral resource instance
#     .vault: planned value cty.StringVal("nb3zfvjlzk3yijqkdgvzruft54")
#             does not match config value cty.StringVal("DevOps")
#
# So a vault data source turns the human-readable name into a UUID. Vault
# names stay in the variables, where a person can read them; UUIDs never
# appear in the configuration.
#
# This is NOT the banned `data "onepassword_item"` (§12.5): a vault data
# source returns a name, a UUID and a description, and no secret can reach it.
data "onepassword_vault" "devops" {
  name = var.op_devops_vault # "DevOps"
}

ephemeral "onepassword_item" "dnsimple" {
  vault = data.onepassword_vault.devops.uuid # UUID, not name
  title = "dnsimple-terraform"
}

ephemeral "onepassword_item" "datadog" {
  vault = data.onepassword_vault.devops.uuid # UUID, not name
  title = "datadog-terraform"
}

locals {
  # Implicitly ephemeral — derived from an ephemeral resource. The regexes
  # tolerate `export FOO="bar"`, `export FOO=bar` and `FOO='bar'`.
  #
  # \\s* on BOTH sides of the delimiter: the DNSimple note has been seen
  # written as `export DNSIMPLE_TOKEN ="…"`, and a space before `=` must not
  # break the plan. R23 — it has already happened once.
  dnsimple_token = regex(
    "DNSIMPLE_TOKEN\\s*[=:]\\s*['\"]?([^'\"\\s]+)",
    ephemeral.onepassword_item.dnsimple.note_value,
  )[0]

  # Only the TOKEN comes from the note. The account id is not a secret and is
  # var.dnsimple_account — see the provider block below.

  _datadog_note   = ephemeral.onepassword_item.datadog.note_value
  datadog_api_key = regex("DD_API_KEY\\s*[=:]\\s*['\"]?([^'\"\\s]+)", local._datadog_note)[0]
  datadog_app_key = regex("DD_APP_KEY\\s*[=:]\\s*['\"]?([^'\"\\s]+)", local._datadog_note)[0]
}

provider "dnsimple" {
  # The note is a shell fragment; §6.2 parses the token out of it. The account
  # id is a plain variable (§6.1) and NOT from the note: the note's
  # DNSIMPLE_ACCOUNT is not the numeric id the API path requires, and using it
  # produces a 401 that reads as an authentication failure rather than an
  # addressing one. R25
  token   = local.dnsimple_token
  account = var.dnsimple_account
}

provider "datadog" {
  api_key = local.datadog_api_key
  app_key = local.datadog_app_key
  api_url = "https://api.${var.datadog_site}"

  # Gated so a workspace with Datadog switched off does not fail `plan` on a
  # credential it is not going to use.
  validate = var.datadog_enabled[terraform.workspace]
}

# ---------------------------------------------------------------------------
# Shared data sources
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
