# Identity, region and the state bucket. §4.3

variable "org_name" {
  description = "[REQUIRED] organisation this deployment belongs to"
  type        = string
  default     = "appliedblockchain"
}

variable "project_name" {
  description = "[REQUIRED] project name — the first component of every resource name"
  type        = string
  default     = "gianotest"
}

variable "aws_region" {
  description = "[REQUIRED] AWS region, per environment. `default` is the bootstrap workspace (§18 step 2)"
  type        = map(string)
  default = {
    default = "eu-west-2"
    dev     = "eu-west-2"
    stg     = "eu-west-2"
    prd     = "eu-west-2"
  }
}

variable "profile" {
  description = "[REQUIRED] AWS CLI profile, per environment. `default` is the bootstrap workspace"
  type        = map(string)
  default = {
    default = "giano-dev"
    dev     = "giano-dev"
    stg     = "giano-stg"
    prd     = "giano-prd"
  }
}

variable "s3_tfstate_name" {
  description = "[REQUIRED] name of the S3 bucket holding state — must match the backend block in _init.tf"
  type        = string
  default     = "giano-tfstate"
}

variable "op_account" {
  description = "[REQUIRED] 1Password account for the desktop-app SDK integration. A variable rather than OP_ACCOUNT in the environment, so nothing has to be exported (§4.6.1)"
  type        = string
  default     = "appliedblockchain.1password.com"
}
