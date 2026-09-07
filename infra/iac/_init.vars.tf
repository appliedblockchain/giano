# Giano — org/project identity and the values that select region, profile and state bucket.
# specs/INFRASTRUCTURE.md §4.3, §4.5, §4.6.1.

variable "org_name" {
  description = "organisation name — carried in default_tags"
  type        = string
  default     = "appliedblockchain"
}

variable "project_name" {
  description = "project name — the first component of every resource name, via local.name_prefix"
  type        = string
  default     = "giano"
}

variable "aws_region" {
  description = "AWS region, per environment — D5: eu-west-2 (London)"
  type        = map(string)
  default = {
    dev = "eu-west-2"
    stg = "eu-west-2"
    prd = "eu-west-2"
  }
}

variable "profile" {
  description = "AWS CLI/SDK profile used by the provider, per environment"
  type        = map(string)
  default = {
    dev = "giano-dev"
    stg = "giano-stg"
    prd = "giano-prd"
  }
}

variable "s3_tfstate_name" {
  description = "name of the S3 state bucket created by bootstrap/ (§4.5) — carried in default_tags"
  type        = string
  default     = "giano-tfstate"
}

# 1Password account for the desktop-app SDK integration — §4.6.1.
variable "op_account" {
  description = "1Password account for the desktop-app SDK integration"
  type        = string
  default     = "applied.1password.com"
}
