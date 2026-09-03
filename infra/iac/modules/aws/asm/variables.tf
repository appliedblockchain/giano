variable "name_prefix" {
  description = "[REQUIRED] prefix for every secret name, e.g. giano-dev"
  type        = string
}

variable "kms_key_id" {
  description = "[REQUIRED] customer-managed KMS key id used to encrypt the secrets"
  type        = string
}

variable "recovery_window_in_days" {
  description = "[REQUIRED] deletion recovery window; 0 deletes immediately"
  type        = number
}

# The static inventory. Comes from the data.external read of the note (§12.4)
# and is what for_each iterates — it MUST be known at plan time.
variable "secrets" {
  description = "[REQUIRED] { key => { version = number } } — names and rotation versions, no values"
  type        = map(object({ version = number }))
}

# The values. Ephemeral: they never enter state, and Terraform enforces that a
# non-ephemeral variable cannot receive them.
variable "values" {
  description = "[REQUIRED] { key => string } — the secret values, from the 1Password bundle"
  type        = map(string)
  ephemeral   = true
  sensitive   = true
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
