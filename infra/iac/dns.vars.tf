variable "dns_zone" {
  description = "[REQUIRED] registrable DNSimple zone for this environment — MUST already exist in DNSimple"
  type        = map(string)
  default = {
    dev = "appliedblockchain.dev"
    stg = "appliedblockchain.dev"
    prd = "appliedblockchain.dev" # expected to change — production gets its own domain
  }
}

variable "dns_prefix" {
  description = "[REQUIRED] hostname prefix under the zone, per environment"
  type        = map(string)
  default = {
    dev = "dev.giano"
    stg = "stg.giano"
    prd = "giano"
  }
}

variable "dnsimple_account" {
  description = "[REQUIRED] DNSimple NUMERIC account id — appears in every API path. Not a secret, so it lives in version control beside the zone rather than in a shared credential note"
  type        = string
  default     = "54212"

  # Not decoration: DNSimple answers 401, not 404, when the value in the path
  # is not an account the token can act on — so a non-numeric value fails
  # looking exactly like a bad token, and costs an hour. R25
  validation {
    condition     = can(regex("^[0-9]+$", var.dnsimple_account))
    error_message = "DNSimple account must be the numeric account id (see GET /v2/whoami), not a UUID or an email."
  }
}

variable "tenant_wallet_hosts" {
  description = "[REQUIRED] stock-UI tenant wallet hostnames — RP IDs, irreversible (R1). Settle these before the first passkey exists"
  type        = map(list(string))
  default = {
    dev = ["wallet.example.dev.giano.appliedblockchain.dev"]
    stg = []
    prd = []
  }
}

variable "dns_record_ttl" {
  description = "[REQUIRED] TTL on the CNAMEs, seconds"
  type        = number
  default     = 300
}
