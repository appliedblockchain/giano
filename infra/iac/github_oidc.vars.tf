# §10.5

variable "gha_allowed_refs" {
  description = "branches allowed to assume giano-dev-gha-deploy — only main in every environment"
  type        = map(list(string))
  default = {
    dev = ["main"]
    stg = ["main"]
    prd = ["main"]
  }
}
