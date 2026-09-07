<<<<<<< HEAD
# §9.2, §13, §14, §20

variable "image_tag" {
  description = "the commit SHA to deploy — set by the deploy workflow (§15), TF_VAR_image_tag rather than a committed default in CI"
=======
# --- Delivery -------------------------------------------------------------

variable "image_tag" {
  description = "[REQUIRED] the tag every service runs. Tags are the commit SHA, never `latest`, and ECR is IMMUTABLE — so the default will not resolve and the first apply's services fail to start, which §18 step 5 says to expect. CI passes -var image_tag=<sha>"
>>>>>>> main
  type        = string
  default     = "latest"
}

<<<<<<< HEAD
variable "ecs_desired_count" {
  description = "1 in dev (D9 — the schedule owns the rest), 2 in stg/prd — §20"
  type        = map(number)
  default     = { dev = 1, stg = 1, prd = 2 }
}

variable "log_retention_in_days" {
  description = "the log router's own CloudWatch group — §9.5"
  type        = map(number)
  default     = { dev = 7, stg = 7, prd = 30 }
}

variable "ecs_enable_execute_command" {
  description = "on in dev, off in prd — §20"
  type        = map(bool)
  default     = { dev = true, stg = true, prd = false }
}

variable "byo_wallet_enabled" {
  description = "dev-only: a real BYO tenant hosts its own UI, so stg/prd carry the tenant row and nothing else (D17, §9.2, §20)"
=======
# --- Ports ----------------------------------------------------------------

variable "container_port" {
  description = "[REQUIRED] the port every ALB-fronted service listens on"
  type        = number
  default     = 8080
}

variable "bundler_port" {
  description = "[REQUIRED] the bundler's port. Reachable from the tasks security group only — it has no ALB target"
  type        = number
  default     = 4337
}

# --- Sizing and behaviour -------------------------------------------------

variable "ecs_desired_count" {
  description = "[REQUIRED] tasks per service, per environment. One in dev: zero redundancy is deliberate, and a second task doubles the largest variable line in the cost table (R5)"
  type        = map(number)
  default     = { dev = 1, stg = 2, prd = 2 }
}

variable "ecs_enable_execute_command" {
  description = "[REQUIRED] `aws ecs execute-command`, per environment — on in dev, off in prd"
>>>>>>> main
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

<<<<<<< HEAD
# ── Chain — §13 ──────────────────────────────────────────────────────────────────────────────
variable "chain_id" {
  description = "Base Sepolia — D2"
  type        = string
  default     = "84532"
}

variable "entrypoint_address" {
  description = "EntryPoint v0.7 — canonical at the same address on every chain"
  type        = string
  default     = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
}

# ⚠ REQUIRED, no default. §13.1: the GianoPaymaster proxy is not frozen in the contracts
# registry for 84532, so this must be a real deployed proxy or sponsorship cannot work at all.
variable "paymaster_address" {
  description = "the deployed GianoPaymaster proxy address for this chain — §13.1, deploy it BEFORE the first apply that enables sponsorship"
  type        = string
  default     = "0xf98b56de62ce88cEb70A9155582248cDBf2D0718"
}

# ⚠ REQUIRED for wallet-byo only (§14.5) — its bundle has no registry dependency, unlike
# wallet-api and wallet-web which default correctly from the contracts registry.
variable "factory_address" {
  description = "GianoSmartWalletFactory address — required by wallet-byo's serve.mjs, which has no contracts-registry dependency"
  type        = string
  default     = "0x26dCd29390eba3B22BcCbd2143989E5994Ac7050"
}

variable "rpc_origin" {
  description = "the RPC origin only (not the keyed URL) — space-separated additions to wallet-web's CSP connect-src. Not a secret; the URL that embeds the key is (§14.3)"
  type        = string
  default     = "https://base-sepolia.g.alchemy.com"
}

# ── Branding — §14.3, §14.4 ─────────────────────────────────────────────────────────────────
variable "example_brand_name" {
  type    = string
  default = "Giano Example"
}

variable "byoui_brand_name" {
  type    = string
  default = "Giano Example (BYO UI)"
=======
variable "ecs_wait_for_steady_state" {
  description = "[OPTIONAL] block the apply until every service stabilises. CI sets this so a failed deploy fails the workflow; a human running plan/apply usually does not want to wait"
  type        = bool
  default     = false
}

variable "byo_wallet_enabled" {
  description = "[REQUIRED] whether this environment hosts tenant `byoui`'s own wallet UI and dApp, per environment. Two tasks no real deployment pays for — a real BYO tenant hosts its own UI — so dev only (D17, §20). Also gates that tenant's DNS records and certificate"
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

# --- Chain. §13 -----------------------------------------------------------

variable "chain_id" {
  description = "[REQUIRED] the chain each environment serves"
  type        = map(number)
  default     = { dev = 84532, stg = 84532, prd = 8453 }
}

variable "chain_name" {
  description = "[REQUIRED] display name of that chain"
  type        = map(string)
  default     = { dev = "Base Sepolia", stg = "Base Sepolia", prd = "Base" }
}

variable "rpc_origin" {
  description = "[REQUIRED] the RPC ORIGIN, for wallet-web's CSP connect-src. Not secret — the URL that embeds the API key is, and that one lives in Secrets Manager (§13.3)"
  type        = map(string)
  default = {
    dev = "https://base-sepolia.g.alchemy.com"
    stg = "https://base-sepolia.g.alchemy.com"
    prd = "https://base-mainnet.g.alchemy.com"
  }
}

variable "paymaster_address" {
  description = "[REQUIRED] the GianoPaymaster proxy, per environment. NOT in the contracts registry for 84532: deploying it is a prerequisite of this environment, not part of it (§13.1, runbook step 4)"
  type        = map(string)
  default = {
    dev = "0x0000000000000000000000000000000000000000"
    stg = "0x0000000000000000000000000000000000000000"
    prd = "0x0000000000000000000000000000000000000000"
  }

  validation {
    condition = alltrue([
      for addr in values(var.paymaster_address) : can(regex("^0x[0-9a-fA-F]{40}$", addr))
    ])
    error_message = "each paymaster_address must be a 20-byte hex address."
  }
}

variable "entrypoint_address" {
  description = "[REQUIRED] EntryPoint v0.7 — canonical at the same address on every chain"
  type        = string
  default     = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
>>>>>>> main
}
