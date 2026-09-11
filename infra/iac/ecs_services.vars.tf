# §9.2, §13, §14, §20

# image_tag is NOT a variable — it is local.image_tag, read from infra/versions.json (§15.1,
# _locals.tf). A `-var` override here would defeat the point of having one file both Terraform
# and the deploy workflow read as the single declared version.

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
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

# ── Chain — §13 ──────────────────────────────────────────────────────────────────────────────
variable "chain_id" {
  description = "chain A — Base Sepolia (D2)"
  type        = string
  default     = "84532"
}

variable "chain_name" {
  description = "chain A display name — custom-example's chainName"
  type        = string
  default     = "Base Sepolia"
}

variable "chain_b_id" {
  description = "chain B — Ethereum Sepolia (D2). Both chains carry the paymaster at the same CREATE2 address (§13.1)"
  type        = string
  default     = "11155111"
}

variable "chain_b_name" {
  description = "chain B display name — custom-example's chainBName"
  type        = string
  default     = "Ethereum Sepolia"
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
  description = "chain A RPC origin only (not the keyed URL) — joined into wallet-web's CSP connect-src. Not a secret; the URL that embeds the key is (§14.3)"
  type        = string
  default     = "https://base-sepolia.quiknode.pro"
}

variable "rpc_b_origin" {
  description = "chain B RPC origin only — the browser dials both chains directly, so both belong in connect-src (§14.3)"
  type        = string
  default     = "https://eth-sepolia.quiknode.pro"
}

# ── Branding — §14.3, §14.4 ─────────────────────────────────────────────────────────────────
variable "example_brand_name" {
  type    = string
  default = "Giano Example"
}

variable "byoui_brand_name" {
  type    = string
  default = "Giano Example (BYO UI)"
}
