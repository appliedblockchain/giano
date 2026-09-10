# §8.1, §8.3

variable "name_prefix" {
  description = "[REQUIRED] e.g. giano-dev"
  type        = string
}

variable "component" {
  description = "[REQUIRED] which database this is, e.g. \"app\" — feeds every resource name"
  type        = string
}

variable "engine_version" {
  description = "[REQUIRED] Postgres major/minor version, e.g. \"17\""
  type        = string
}

variable "instance_class" {
  description = "[REQUIRED] e.g. db.t4g.micro"
  type        = string
}

variable "allocated_storage" {
  description = "[REQUIRED] initial storage, GB"
  type        = number
}

variable "storage_autoscale_max" {
  description = "[REQUIRED] max_allocated_storage, GB"
  type        = number
}

variable "multi_az" {
  description = "[REQUIRED] false in dev — see §2.2"
  type        = bool
}

variable "backup_retention_period" {
  description = "[REQUIRED] days"
  type        = number
}

variable "deletion_protection" {
  description = "[REQUIRED] false in dev, true in stg/prd"
  type        = bool
}

variable "skip_final_snapshot" {
  description = "[REQUIRED] true in dev, false in stg/prd"
  type        = bool
}

variable "db_name" {
  description = "[REQUIRED] the initial database name"
  type        = string
}

variable "db_username" {
  description = "[REQUIRED] the master username"
  type        = string
}

# write-only — §8.3. random_password is rejected: its result would be stored in state,
# forever, and would be the one exception that makes the "no secrets in state" guarantee
# useless.
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
  description = "[REQUIRED] customer-managed KMS key ARN encrypting storage at rest — cannot change after creation"
  type        = string
}

variable "vpc_id" {
  description = "[REQUIRED]"
  type        = string
}

variable "subnet_ids" {
  description = "[REQUIRED] private subnet ids for the DB subnet group"
  type        = list(string)
}

variable "source_sg_id" {
  description = "[REQUIRED] the tasks security group — the ONLY thing granted ingress on 5432"
  type        = string
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
