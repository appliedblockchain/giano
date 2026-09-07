variable "name" {
<<<<<<< HEAD
  description = "[REQUIRED] the role's full name — the caller composes it, e.g. \"giano-dev-scheduler\""
  type        = string
}

variable "assume_role_policy_json" {
  description = "[REQUIRED] JSON assume-role policy document, built by the caller via data.aws_iam_policy_document"
  type        = string
}

variable "inline_policy_json" {
  description = "[REQUIRED] a single inline policy document JSON to attach to the role — required (not nullable) so the aws_iam_role_policy resource is never count-gated on it; see the comment in iam.tf"
  type        = string
}

variable "managed_policy_arns" {
  description = "[OPTIONAL] AWS-managed or customer-managed policy ARNs to attach"
=======
  description = "[REQUIRED] role name, already prefixed by the caller"
  type        = string
}

variable "description" {
  description = "[REQUIRED] what this role is for"
  type        = string
}

variable "assume_role_policy" {
  description = "[REQUIRED] the trust policy, as JSON — build it with data.aws_iam_policy_document (D19)"
  type        = string
}

variable "inline_policies" {
  description = "[OPTIONAL] { policy name => policy JSON } attached inline to the role"
  type        = map(string)
  default     = {}
}

variable "managed_policy_arns" {
  description = "[OPTIONAL] customer-managed policy ARNs to attach. AWS-managed AmazonECSTaskExecutionRolePolicy is deliberately NOT used anywhere — it grants ECR pull and log write across the whole account (§10.2)"
>>>>>>> main
  type        = list(string)
  default     = []
}

<<<<<<< HEAD
=======
variable "max_session_duration" {
  description = "[OPTIONAL] maximum session duration, seconds"
  type        = number
  default     = 3600
}

>>>>>>> main
variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
