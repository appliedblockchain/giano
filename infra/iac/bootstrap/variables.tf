# bootstrap/ is applied once, unscoped by environment — there is no terraform.workspace concept
# here (§4.5), so these are plain variables rather than the main root module's per-workspace maps.

variable "aws_region" {
  description = "AWS region for the state bucket — D5: eu-west-2 (London)"
  type        = string
  default     = "eu-west-2"
}

variable "profile" {
  description = "AWS CLI/SDK profile used once, by hand, to create the state bucket"
  type        = string
  default     = "default"
}
