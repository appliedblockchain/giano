<<<<<<< HEAD
# Giano — org/project identity and the values that select region, profile and state bucket.
# specs/INFRASTRUCTURE.md §4.3, §4.5, §4.6.1.

variable "org_name" {
  description = "organisation name — carried in default_tags"
=======
# Identity, region and the state bucket. §4.3

variable "org_name" {
  description = "[REQUIRED] organisation this deployment belongs to"
>>>>>>> main
  type        = string
  default     = "appliedblockchain"
}

variable "project_name" {
<<<<<<< HEAD
  description = "project name — the first component of every resource name, via local.name_prefix"
  type        = string
  default     = "giano"
}

variable "aws_region" {
  description = "AWS region, per environment — D5: eu-west-2 (London)"
=======
  description = "[REQUIRED] project name — the first component of every resource name"
  type        = string
  default     = "gianotest"
}

variable "aws_region" {
  description = "[REQUIRED] AWS region, per environment. No `default` key: that workspace is never used, so an apply there fails on a missing key rather than building something unnamed (§4.1)"
>>>>>>> main
  type        = map(string)
  default = {
    dev = "eu-west-2"
    stg = "eu-west-2"
    prd = "eu-west-2"
  }
}

variable "profile" {
<<<<<<< HEAD
  description = "AWS CLI/SDK profile used by the provider, per environment"
=======
  description = "[REQUIRED] AWS CLI profile, per environment"
>>>>>>> main
  type        = map(string)
  default = {
    dev = "default"
    stg = "default"
    prd = "default"
  }
}

variable "s3_tfstate_name" {
<<<<<<< HEAD
  description = "name of the S3 state bucket created by bootstrap/ (§4.5) — carried in default_tags"
=======
  description = "[REQUIRED] name of the S3 bucket holding state — must match the backend block in _init.tf"
>>>>>>> main
  type        = string
  default     = "giano-tfstate"
}

<<<<<<< HEAD
# 1Password account for the desktop-app SDK integration — §4.6.1.
variable "op_account" {
  description = "1Password account for the desktop-app SDK integration"
=======
variable "op_account" {
  description = "[REQUIRED] 1Password account for the desktop-app SDK integration. A variable rather than OP_ACCOUNT in the environment, so nothing has to be exported (§4.6.1)"
>>>>>>> main
  type        = string
  default     = "applied.1password.com"
}
