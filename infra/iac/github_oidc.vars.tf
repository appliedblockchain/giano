# §10.5

variable "gha_allowed_refs" {
  description = "branches allowed to assume giano-dev-gha-deploy — dev can trust a feature branch, prd only main"
  type        = map(list(string))
  default = {
    dev = ["main", "docs/dev-infrastructure-spec"]
    stg = ["main"]
    prd = ["main"]
  }
}
