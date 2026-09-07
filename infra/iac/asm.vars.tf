<<<<<<< HEAD
# §7.3, §12.2

variable "asm_recovery_window_in_days" {
  description = "ASM deletion recovery window, per environment — 30 everywhere, including dev (§7.3): a value deleted from the note destroys the ASM secret, and this is the window in which that is recoverable"
  type        = map(number)
  default     = { dev = 30, stg = 30, prd = 30 }
}

# ── 1Password vault coordinates — §12.2 ─────────────────────────────────────────────────────
variable "op_vault_suffix" {
  description = "1Password vault suffix per environment — prd is deliberately isolated in its own vault"
=======
# --- 1Password. §12.2 -----------------------------------------------------
#
# Three vaults, and the split is deliberate:
#
#   DevOps          dnsimple-terraform, datadog-terraform — provider
#                   credentials, shared with every other project (§4.6.1)
#   Giano dev/stg   secrets-dev, secrets-stg
#   Giano prd       secrets-prd, and nothing else
#
# The names compose in _locals.tf into local.op_vault and local.op_item.

variable "op_vault_suffix" {
  description = "[REQUIRED] 1Password vault suffix per environment — prd is deliberately isolated"
>>>>>>> main
  type        = map(string)
  default = {
    dev = "dev/stg"
    stg = "dev/stg"
    prd = "prd"
  }
}

variable "op_devops_vault" {
<<<<<<< HEAD
  description = "shared vault holding provider credentials (dnsimple-terraform, datadog-terraform)"
=======
  description = "[REQUIRED] shared vault holding provider credentials"
>>>>>>> main
  type        = string
  default     = "DevOps"
}

<<<<<<< HEAD
variable "db_username" {
  description = "RDS master username, per environment"
  type        = map(string)
  default = {
    dev = "giano"
    stg = "giano"
    prd = "giano"
  }
=======
# --- Secrets Manager ------------------------------------------------------

variable "asm_recovery_window_in_days" {
  description = "[REQUIRED] ASM deletion recovery window, per environment. 30 everywhere, including dev: deleting a key from the 1Password note DESTROYS the corresponding secret (R8), and this is the window in which that is recoverable"
  type        = map(number)
  default     = { dev = 30, stg = 30, prd = 30 }
}

variable "datadog_api_key_version" {
  description = "[REQUIRED] rotation trigger for the ASM mirror of the shared Datadog API key — bump by hand whenever that key is rotated in 1Password (R24)"
  type        = number
  default     = 1
>>>>>>> main
}
