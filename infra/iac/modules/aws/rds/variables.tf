<<<<<<< HEAD
# §8.1, §8.3

variable "name_prefix" {
  description = "[REQUIRED] e.g. giano-dev"
=======
variable "name_prefix" {
  description = "[REQUIRED] prefix for every resource name, e.g. giano-dev"
>>>>>>> main
  type        = string
}

variable "component" {
<<<<<<< HEAD
  description = "[REQUIRED] which database this is, e.g. \"app\" — feeds every resource name"
=======
  description = "[REQUIRED] what this database is for, e.g. `app` — the second half of every name"
>>>>>>> main
  type        = string
}

variable "engine_version" {
<<<<<<< HEAD
  description = "[REQUIRED] Postgres major/minor version, e.g. \"17\""
=======
  description = "[REQUIRED] Postgres major version"
>>>>>>> main
  type        = string
}

variable "instance_class" {
<<<<<<< HEAD
  description = "[REQUIRED] e.g. db.t4g.micro"
=======
  description = "[REQUIRED] instance class"
>>>>>>> main
  type        = string
}

variable "allocated_storage" {
<<<<<<< HEAD
  description = "[REQUIRED] initial storage, GB"
=======
  description = "[REQUIRED] allocated storage, GB"
>>>>>>> main
  type        = number
}

variable "storage_autoscale_max" {
<<<<<<< HEAD
  description = "[REQUIRED] max_allocated_storage, GB"
=======
  description = "[REQUIRED] maximum storage autoscaling will grow to, GB"
>>>>>>> main
  type        = number
}

variable "multi_az" {
<<<<<<< HEAD
  description = "[REQUIRED] false in dev — see §2.2"
=======
  description = "[REQUIRED] whether the instance is multi-AZ — false in dev"
>>>>>>> main
  type        = bool
}

variable "backup_retention_period" {
<<<<<<< HEAD
  description = "[REQUIRED] days"
=======
  description = "[REQUIRED] automated backup retention, days"
>>>>>>> main
  type        = number
}

variable "deletion_protection" {
<<<<<<< HEAD
  description = "[REQUIRED] false in dev, true in stg/prd"
=======
  description = "[REQUIRED] whether the instance refuses to be destroyed"
>>>>>>> main
  type        = bool
}

variable "skip_final_snapshot" {
<<<<<<< HEAD
  description = "[REQUIRED] true in dev, false in stg/prd"
=======
  description = "[REQUIRED] whether destroying the instance skips a final snapshot"
>>>>>>> main
  type        = bool
}

variable "db_name" {
<<<<<<< HEAD
  description = "[REQUIRED] the initial database name"
=======
  description = "[REQUIRED] initial database name"
>>>>>>> main
  type        = string
}

variable "db_username" {
<<<<<<< HEAD
  description = "[REQUIRED] the master username"
  type        = string
}

# write-only — §8.3. random_password is rejected: its result would be stored in state,
# forever, and would be the one exception that makes the "no secrets in state" guarantee
# useless.
=======
  description = "[REQUIRED] master username"
  type        = string
}

>>>>>>> main
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
<<<<<<< HEAD
  description = "[REQUIRED] customer-managed KMS key ARN encrypting storage at rest — cannot change after creation"
=======
  description = "[REQUIRED] customer-managed KMS key ARN for storage encryption. CANNOT be changed after creation (R12)"
>>>>>>> main
  type        = string
}

variable "vpc_id" {
<<<<<<< HEAD
  description = "[REQUIRED]"
=======
  description = "[REQUIRED] VPC the instance and its security group live in"
>>>>>>> main
  type        = string
}

variable "subnet_ids" {
<<<<<<< HEAD
  description = "[REQUIRED] private subnet ids for the DB subnet group"
=======
  description = "[REQUIRED] private subnets for the subnet group"
>>>>>>> main
  type        = list(string)
}

variable "source_sg_id" {
<<<<<<< HEAD
  description = "[REQUIRED] the tasks security group — the ONLY thing granted ingress on 5432"
  type        = string
}

=======
  description = "[REQUIRED] the security group allowed to reach 5432 — the ECS tasks group, never a VPC CIDR"
  type        = string
}

variable "log_min_duration_statement" {
  description = "[OPTIONAL] log statements slower than this, ms"
  type        = number
  default     = 1000
}

>>>>>>> main
variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
