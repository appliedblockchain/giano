# §6.1, §18.1 step 2

variable "dns_zone" {
  description = "registrable DNSimple zone for this environment — MUST already exist in DNSimple"
  type        = map(string)
  default = {
    dev = "appliedblockchain.dev"
    stg = "appliedblockchain.dev"
    prd = "appliedblockchain.dev" # expected to change — production gets its own domain
  }
}

variable "dns_prefix" {
  description = "hostname prefix under the zone, per environment"
  type        = map(string)
  default = {
    dev = "dev.giano"
    stg = "stg.giano"
    prd = "giano"
  }
}

variable "dnsimple_account" {
  description = "DNSimple NUMERIC account id — appears in every API path. Not a secret."
  type        = string
  default     = "54212"

  validation {
    condition     = can(regex("^[0-9]+$", var.dnsimple_account))
    error_message = "DNSimple account must be the numeric account id (see GET /v2/whoami), not a UUID or an email."
  }
}

# §18.1 step 2 — settle this now. Passkeys bind to these hostnames irreversibly (R1).
variable "tenant_wallet_hosts" {
  description = "stock-UI tenant wallet hostnames — RP IDs, irreversible"
  type        = map(list(string))
  default = {
    dev = ["wallet.example.dev.giano.appliedblockchain.dev"]
    stg = []
    prd = []
  }
}
