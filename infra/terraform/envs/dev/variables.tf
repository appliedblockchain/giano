# Nothing in this file is a secret, and nothing in it may become one. Private keys, admin keys
# and the RPC URL live in SSM and are written out of band (spec §9.1) — a secret passed as a
# Terraform variable is a secret in state and, sooner or later, in a pull request.

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "environment" {
  type        = string
  description = "Environment discriminator. Names every resource and scopes the SSM path."
  default     = "dev"
}

# ── DNS ────────────────────────────────────────────────────────────────────────────────────

variable "parent_domain" {
  type        = string
  description = "The zone the NS delegation is added to by hand, e.g. giano.example.com."
}

variable "subdomain" {
  type        = string
  description = "Child zone label. With parent giano.example.com, `dev` yields dev.giano.example.com."
  default     = "dev"
}

# ── chain ──────────────────────────────────────────────────────────────────────────────────

variable "chain_id" {
  type        = number
  description = "Base Sepolia. In the giano-contracts registry, so EntryPoint and factory default correctly."
  default     = 84532

  validation {
    # The boot-time chain check refuses a chain whose factory is not the canonical one, and the
    # registry is what supplies that address. A chain that is not in it needs explicit
    # ENTRYPOINT_ADDRESS/FACTORY_ADDRESS, which this root module does not set.
    condition     = contains([8453, 84532], var.chain_id)
    error_message = "Only chains in the giano-contracts address registry (8453, 84532) work without explicit contract addresses."
  }
}

variable "chain_name" {
  type    = string
  default = "Base Sepolia"
}

variable "paymaster_address" {
  type        = string
  description = <<-EOT
    The GianoPaymaster proxy on this chain. There is NO registry entry for it on 84532 — it
    must be deployed first (spec §6.1):

      pnpm --filter @appliedblockchain/giano-contracts hh:deploy:paymaster --network base-sepolia

    Leave empty to bring the stack up with sponsorship disabled.
  EOT
  default     = ""

  validation {
    condition     = var.paymaster_address == "" || can(regex("^0x[0-9a-fA-F]{40}$", var.paymaster_address))
    error_message = "paymaster_address must be empty or a 20-byte hex address."
  }
}

variable "sponsorship_enabled" {
  type        = bool
  description = "Requires paymaster_address and the sponsorship signer key in SSM."
  default     = true
}

# ── images ─────────────────────────────────────────────────────────────────────────────────

variable "image_tag" {
  type        = string
  description = <<-EOT
    Commit SHA, never `latest` (spec §10.1). This seeds the FIRST task-definition revision;
    afterwards CI registers new revisions and the services ignore changes to task_definition,
    so changing this alone will not redeploy anything.
  EOT
  default     = "bootstrap"
}

# ── behaviour ──────────────────────────────────────────────────────────────────────────────

variable "open_registration" {
  type        = bool
  description = <<-EOT
    Anyone who can reach the environment may create a wallet. Defensible in dev and only in
    dev — the first thing to turn off if the hostname circulates (spec §17 R4).
  EOT
  default     = true
}

variable "brand_name" {
  type    = string
  default = "Giano Dev"
}

variable "enable_schedule" {
  type        = bool
  description = "Out-of-hours scale-to-zero (spec §13). Set false for a demo week."
  default     = true
}

variable "schedule_up_cron" {
  type    = string
  default = "0 7 ? * MON-FRI *"
}

variable "schedule_down_cron" {
  type    = string
  default = "0 19 ? * MON-FRI *"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

# ── CI ─────────────────────────────────────────────────────────────────────────────────────

variable "github_repository" {
  type    = string
  default = "appliedblockchain/giano"
}

variable "github_allowed_refs" {
  type        = list(string)
  description = "Refs permitted to assume the deploy role."
  default     = ["refs/heads/experimental_infrastructure"]
}

variable "create_github_oidc_provider" {
  type        = bool
  description = "False if the AWS account already has the GitHub OIDC provider."
  default     = true
}
