<<<<<<< HEAD
# bootstrap/ is applied once, unscoped by environment — there is no terraform.workspace concept
# here (§4.5), so these are plain variables rather than the main root module's per-workspace maps.

variable "aws_region" {
  description = "AWS region for the state bucket — D5: eu-west-2 (London)"
=======
# Plain strings, not maps keyed by workspace: there is one state bucket for the
# whole project, and this module has no environments.
#
# These defaults MUST match ../_init.vars.tf — this is a separate root module,
# so it cannot read the main one's variables. project_name only feeds tags;
# s3_tfstate_name and aws_region have to agree with the backend block or the
# main module initialises against a bucket that is not this one.

variable "org_name" {
  description = "[REQUIRED] organisation this deployment belongs to"
  type        = string
  default     = "appliedblockchain"
}

variable "project_name" {
  description = "[REQUIRED] project name"
  type        = string
  default     = "gianotest"
}

variable "aws_region" {
  description = "[REQUIRED] region the bucket lives in — MUST match the backend block in ../_init.tf"
>>>>>>> main
  type        = string
  default     = "eu-west-2"
}

variable "profile" {
<<<<<<< HEAD
  description = "AWS CLI/SDK profile used once, by hand, to create the state bucket"
  type        = string
  default     = "default"
}
=======
  description = "[REQUIRED] AWS CLI profile used to create the bucket"
  type        = string
  default     = "default"
}

variable "s3_tfstate_name" {
  description = "[REQUIRED] name of the state bucket — MUST match the backend block in ../_init.tf"
  type        = string
  default     = "gianotest-tfstate"
}
>>>>>>> main
