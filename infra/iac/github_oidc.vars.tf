<<<<<<< HEAD
# §10.5

variable "gha_allowed_refs" {
  description = "branches allowed to assume giano-dev-gha-deploy — dev can trust a feature branch, prd only main"
=======
variable "gha_repository" {
  description = "[REQUIRED] the repository whose workflows may assume the deploy role"
  type        = string
  default     = "appliedblockchain/giano"
}

variable "gha_allowed_refs" {
  description = "[REQUIRED] branches that may assume the deploy role, per environment. dev can trust a feature branch; prd trusts main and nothing else"
>>>>>>> main
  type        = map(list(string))
  default = {
    dev = ["main", "docs/dev-infrastructure-spec"]
    stg = ["main"]
    prd = ["main"]
  }
}
<<<<<<< HEAD
=======

variable "gha_create_oidc_provider" {
  description = "[REQUIRED] whether this workspace creates the OIDC provider. It is account-global, so exactly one may — the others reference it by ARN"
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

variable "gha_oidc_thumbprints" {
  description = "[OPTIONAL] certificate thumbprints for the OIDC provider. AWS trusts GitHub's chain natively, so this is empty and kept only for the day it is not"
  type        = list(string)
  default     = []
}
>>>>>>> main
