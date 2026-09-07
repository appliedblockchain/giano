<<<<<<< HEAD
# §8.1 — D4: RDS Postgres 17, db.t4g.micro, single-AZ in dev.

variable "app-db-engine-version" {
  type    = map(string)
  default = { dev = "17", stg = "17", prd = "17" }
}

variable "app-db-instance-class" {
  type    = map(string)
  default = { dev = "db.t4g.micro", stg = "db.t4g.micro", prd = "db.t4g.small" }
}

variable "app-db-allocated-storage" {
  type    = map(number)
  default = { dev = 20, stg = 20, prd = 50 }
}

variable "app-db-storage-autoscale-max" {
  type    = map(number)
  default = { dev = 50, stg = 50, prd = 200 }
}

variable "app-db-multi-az" {
  description = "false in dev — §2.2, §20"
=======
variable "app-db-engine-version" {
  description = "[REQUIRED] Postgres major version, per environment"
  type        = map(string)
  default     = { dev = "17", stg = "17", prd = "17" }
}

variable "app-db-instance-class" {
  description = "[REQUIRED] instance class, per environment"
  type        = map(string)
  default     = { dev = "db.t4g.micro", stg = "db.t4g.small", prd = "db.t4g.medium" }
}

variable "app-db-allocated-storage" {
  description = "[REQUIRED] allocated storage in GB, per environment"
  type        = map(number)
  default     = { dev = 20, stg = 20, prd = 50 }
}

variable "app-db-storage-autoscale-max" {
  description = "[REQUIRED] storage autoscaling ceiling in GB, per environment"
  type        = map(number)
  default     = { dev = 50, stg = 100, prd = 500 }
}

variable "app-db-multi-az" {
  description = "[REQUIRED] multi-AZ, per environment. Single-AZ in dev — the NETWORK is still two-AZ (§5)"
>>>>>>> main
  type        = map(bool)
  default     = { dev = false, stg = false, prd = true }
}

variable "app-db-backup-retention" {
<<<<<<< HEAD
  type    = map(number)
  default = { dev = 7, stg = 7, prd = 14 }
}

variable "app-db-deletion-protection" {
  description = "false in dev, true in stg/prd — §20"
  type        = map(bool)
  default     = { dev = false, stg = false, prd = true }
}

variable "app-db-skip-final-snapshot" {
  description = "true in dev, false in stg/prd — §20"
  type        = map(bool)
  default     = { dev = true, stg = true, prd = false }
=======
  description = "[REQUIRED] automated backup retention in days, per environment"
  type        = map(number)
  default     = { dev = 7, stg = 7, prd = 30 }
}

variable "app-db-deletion-protection" {
  description = "[REQUIRED] deletion protection, per environment"
  type        = map(bool)
  default     = { dev = false, stg = true, prd = true }
}

variable "app-db-skip-final-snapshot" {
  description = "[REQUIRED] skip the final snapshot on destroy, per environment"
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

variable "app-db-username" {
  description = "[REQUIRED] master username, per environment. The password is hand-authored in 1Password as `database-password` (§8.3)"
  type        = map(string)
  default     = { dev = "giano", stg = "giano", prd = "giano" }
>>>>>>> main
}
