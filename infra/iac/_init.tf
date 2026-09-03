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

ephemeral "onepassword_item" "dnsimple" {
  vault = var.op_devops_vault # "DevOps"
  title = "dnsimple-terraform"
}

ephemeral "onepassword_item" "datadog" {
  vault = var.op_devops_vault # "DevOps"
  title = "datadog-terraform"
}

locals {
  # Implicitly ephemeral — derived from an ephemeral resource. The regexes
  # tolerate `export FOO="bar"`, `export FOO=bar` and `FOO='bar'`. R23.
  _dnsimple_note = ephemeral.onepassword_item.dnsimple.note_value
  _datadog_note  = ephemeral.onepassword_item.datadog.note_value

  dnsimple_token   = regex("DNSIMPLE_TOKEN[=:]\\s*['\"]?([^'\"\\s]+)", local._dnsimple_note)[0]
  dnsimple_account = regex("DNSIMPLE_ACCOUNT[=:]\\s*['\"]?([^'\"\\s]+)", local._dnsimple_note)[0]

  datadog_api_key = regex("DD_API_KEY[=:]\\s*['\"]?([^'\"\\s]+)", local._datadog_note)[0]
  datadog_app_key = regex("DD_APP_KEY[=:]\\s*['\"]?([^'\"\\s]+)", local._datadog_note)[0]
}

provider "dnsimple" {
  # the note is a shell fragment; the two values are parsed out of it above
  token   = local.dnsimple_token
  account = local.dnsimple_account
}

provider "datadog" {
  api_key = local.datadog_api_key
  app_key = local.datadog_app_key
  api_url = "https://api.${var.datadog_site}"

  # Gated so a workspace with Datadog switched off does not fail `plan` on a
  # credential it is not going to use. `lookup` because the `default`
  # bootstrap workspace (§4.1) is not a key in the map.
  validate = lookup(var.datadog_enabled, terraform.workspace, false)
}

# ---------------------------------------------------------------------------
# Shared data sources
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}
