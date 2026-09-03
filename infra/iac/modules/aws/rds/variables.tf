variable "name_prefix" {
  description = "[REQUIRED] prefix for every resource name, e.g. giano-dev"
  type        = string
}

variable "component" {
  description = "[REQUIRED] what this database is for, e.g. `app` — the second half of every name"
  type        = string
}

variable "engine_version" {
  description = "[REQUIRED] Postgres major version"
  type        = string
}

variable "instance_class" {
  description = "[REQUIRED] instance class"
  type        = string
}

variable "allocated_storage" {
  description = "[REQUIRED] allocated storage, GB"
  type        = number
}

variable "storage_autoscale_max" {
  description = "[REQUIRED] maximum storage autoscaling will grow to, GB"
  type        = number
}

variable "multi_az" {
  description = "[REQUIRED] whether the instance is multi-AZ — false in dev"
  type        = bool
}

variable "backup_retention_period" {
  description = "[REQUIRED] automated backup retention, days"
  type        = number
}

variable "deletion_protection" {
  description = "[REQUIRED] whether the instance refuses to be destroyed"
  type        = bool
}

variable "skip_final_snapshot" {
  description = "[REQUIRED] whether destroying the instance skips a final snapshot"
  type        = bool
}

variable "db_name" {
  description = "[REQUIRED] initial database name"
  type        = string
}

variable "db_username" {
  description = "[REQUIRED] master username"
  type        = string
}

variable "db_password_wo" {
  description = "[REQUIRED] master password, write-only — never persisted to state"
  type        = string
  ephemeral   = true
  sensitive   = true
}

variable "db_password_wo_version" {
  description = "[REQUIRED] bump to rotate the master password"
  type        = number
}

variable "kms_key_id" {
  description = "[REQUIRED] customer-managed KMS key ARN for storage encryption. CANNOT be changed after creation (R12)"
  type        = string
}

variable "vpc_id" {
  description = "[REQUIRED] VPC the instance and its security group live in"
  type        = string
}

variable "subnet_ids" {
  description = "[REQUIRED] private subnets for the subnet group"
  type        = list(string)
}

variable "source_sg_id" {
  description = "[REQUIRED] the security group allowed to reach 5432 — the ECS tasks group, never a VPC CIDR"
  type        = string
}

variable "log_min_duration_statement" {
  description = "[OPTIONAL] log statements slower than this, ms"
  type        = number
  default     = 1000
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
