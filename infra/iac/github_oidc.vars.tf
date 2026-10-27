# §10.5

variable "gha_allowed_refs" {
  description = "branches allowed to assume giano-<env>-gha-deploy — dev can trust a feature branch; prd only the protected production branch (ABIP-1)"
  type        = map(list(string))
  default = {
    dev = ["main", "docs/dev-infrastructure-spec"]
    stg = ["main"]
    prd = ["production"]
  }
}
