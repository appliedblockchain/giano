variable "name" {
  type        = string
  description = "Resource name prefix, e.g. giano-dev."
}

variable "github_repository" {
  type        = string
  description = "owner/repo, e.g. appliedblockchain/giano."
}

variable "allowed_refs" {
  type        = list(string)
  description = <<-EOT
    Git refs permitted to assume the deploy role, as they appear in the OIDC `sub` claim
    after `repo:<owner>/<repo>:ref:`. Pull requests from forks never match these, which is
    the point. Add refs/heads/main when the work merges.
  EOT
  default     = ["refs/heads/experimental_infrastructure"]
}

variable "create_oidc_provider" {
  type        = bool
  description = "False if the account already has the GitHub OIDC provider; pass its ARN instead."
  default     = true
}

variable "oidc_provider_arn" {
  type        = string
  description = "Existing provider ARN, used when create_oidc_provider is false."
  default     = null
}

variable "cluster_arn" {
  type        = string
  description = "Scopes every ECS action to this cluster."
}

variable "cluster_name" {
  type        = string
  description = "Scopes log reads to this cluster's log groups."
}

variable "ecr_repository_arns" {
  type        = list(string)
  description = "Repositories the workflow may push to."
}

variable "passable_role_arns" {
  type        = list(string)
  description = "Task execution role plus every task role. Never a wildcard."
}
