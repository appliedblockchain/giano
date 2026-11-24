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

# The GianoPaymaster proxy, release v3: the same CREATE3 address on both testnets (§13.1;
# packages/contracts/deployments/84532.json and 11155111.json). Read by the provision-sponsorship
# one-shot task. The legacy v0.7 paymaster was 0xf98b56de62ce88cEb70A9155582248cDBf2D0718.
variable "paymaster_address" {
  description = "the deployed GianoPaymaster proxy address (release v3, both testnets) — §13.1"
  type        = string
  default     = "0xb2C7081be89D88f1da020530Ebd5c14b8871615a"
}

# ⚠ REQUIRED for wallet-byo only (§14.5) — its bundle has no registry dependency, unlike
# wallet-api and wallet-web which default correctly from the contracts registry.
# Release v3, the same CREATE3 address on both testnets. The legacy v0.7 factory was
# 0x26dCd29390eba3B22BcCbd2143989E5994Ac7050.
variable "factory_address" {
  description = "GianoSmartWalletFactory address — required by wallet-byo's serve.mjs, which has no contracts-registry dependency"
  type        = string
  default     = "0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635"
}

# Giano's test ERC-20 (PrivateERC20, anyone may mint): the reference dApp's default token, per
# workspace. dev only: the same CREATE3 address on both testnets (deploy:cli test-token; registry
# field testErc20). Empty elsewhere, so stg and prd get no defaultToken (the dApp reads a blank one
# as unset); a mainnet never carries the token (R-29).
variable "test_erc20_address" {
  description = "the reference dApp's default token per workspace (dev: Giano's test ERC-20); empty for none"
  type        = map(string)
  default = {
    dev = "0x461E0641a3615336b7D2E4C5D71fB2BB88038C93"
    stg = ""
    prd = ""
  }
}

# Silent Data chains per workspace (openspec silent-data-network, H6). dev only: iron-kestrel,
# the one adopted Silent Data chain, where the RPC enforces private reads, so the dApp's private
# token card works. Each entry is added to wallet-web's and custom-example's chain lists. The
# chain's backend entry (wallet-api, bundler, console) is in the `chains` secret, with the tokened
# write URL as bundler.rpcUrl (deploy/contracts/TESTNET-ROLLOUT.md, "Adding iron-kestrel to dev").
variable "silent_data_chains" {
  description = "Silent Data chains per workspace, added to the chain lists of wallet-web, wallet-byo and both custom-example dApps (dev: iron-kestrel)"
  type = map(list(object({
    chain_id      = number
    name          = string
    rpc_url       = string
    private_token = string
  })))
  default = {
    dev = [{
      chain_id      = 19874
      name          = "Iron Kestrel (Silent Data)"
      rpc_url       = "https://iron-kestrel.silentdata.com"
      private_token = "0xFA7B71b9A5397b8A4faCC9127BE1C665f2F2cA9b"
    }]
    stg = []
    prd = []
  }
}

# rpc_origin / rpc_b_origin (wallet-web's CSP connect-src for direct browser RPC) are gone: the
# SPA no longer dials either chain's node directly, only wallet-api's same-origin relay — R3.

# ── Branding — §14.3, §14.4 ─────────────────────────────────────────────────────────────────
variable "example_brand_name" {
  type    = string
  default = "Giano Example"
}

variable "byoui_brand_name" {
  type    = string
  default = "Giano Example (BYO UI)"
}
