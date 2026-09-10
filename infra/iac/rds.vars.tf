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
  type        = map(bool)
  default     = { dev = false, stg = false, prd = true }
}

variable "app-db-backup-retention" {
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
}
