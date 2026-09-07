# §7.3, §12.2

variable "asm_recovery_window_in_days" {
  description = "ASM deletion recovery window, per environment — 30 everywhere, including dev (§7.3): a value deleted from the note destroys the ASM secret, and this is the window in which that is recoverable"
  type        = map(number)
  default     = { dev = 30, stg = 30, prd = 30 }
}

# ── 1Password vault coordinates — §12.2 ─────────────────────────────────────────────────────
variable "op_vault_suffix" {
  description = "1Password vault suffix per environment — prd is deliberately isolated in its own vault"
  type        = map(string)
  default = {
    dev = "dev/stg"
    stg = "dev/stg"
    prd = "prd"
  }
}

variable "op_devops_vault" {
  description = "shared vault holding provider credentials (dnsimple-terraform, datadog-terraform)"
  type        = string
  default     = "DevOps"
}

variable "db_username" {
  description = "RDS master username, per environment"
  type        = map(string)
  default = {
    dev = "giano"
    stg = "giano"
    prd = "giano"
  }
}
