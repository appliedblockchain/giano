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
