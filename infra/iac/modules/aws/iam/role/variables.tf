variable "name" {
  description = "[REQUIRED] the role's full name — the caller composes it, e.g. \"giano-dev-scheduler\""
  type        = string
}

variable "assume_role_policy_json" {
  description = "[REQUIRED] JSON assume-role policy document, built by the caller via data.aws_iam_policy_document"
  type        = string
}

variable "inline_policy_json" {
  description = "[OPTIONAL] a single inline policy document JSON to attach to the role"
  type        = string
  default     = null
  nullable    = true
}

variable "managed_policy_arns" {
  description = "[OPTIONAL] AWS-managed or customer-managed policy ARNs to attach"
  type        = list(string)
  default     = []
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
