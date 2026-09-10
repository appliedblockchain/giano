variable "name" {
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
  type        = list(string)
  default     = []
}

variable "max_session_duration" {
  description = "[OPTIONAL] maximum session duration, seconds"
  type        = number
  default     = 3600
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
