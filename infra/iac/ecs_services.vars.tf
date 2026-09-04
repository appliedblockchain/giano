# --- Delivery -------------------------------------------------------------

variable "image_tag" {
  description = "[REQUIRED] the tag every service runs. Tags are the commit SHA, never `latest`, and ECR is IMMUTABLE — so the default will not resolve and the first apply's services fail to start, which §18 step 5 says to expect. CI passes -var image_tag=<sha>"
  type        = string
  default     = "latest"
}

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
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

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
}
