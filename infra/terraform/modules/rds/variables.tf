variable "name" {
  type        = string
  description = "Instance identifier, e.g. giano-dev."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private subnets, two AZs (RDS requires two even when single-AZ)."
}

variable "security_group_id" {
  type = string
}

variable "ssm_path_prefix" {
  type        = string
  description = "Where the composed DATABASE_URL is written, e.g. /giano/dev."
}

variable "engine_version" {
  type    = string
  default = "17"
}

variable "instance_class" {
  type        = string
  description = "db.t4g.micro is ~$13/mo and ample for a dev environment."
  default     = "db.t4g.micro"
}

variable "database_name" {
  type    = string
  default = "giano"
}

variable "master_username" {
  type    = string
  default = "giano"
}

variable "allocated_storage" {
  type    = number
  default = 20
}

variable "max_allocated_storage" {
  type        = number
  description = "Storage autoscaling ceiling. 0 disables it."
  default     = 50
}

variable "multi_az" {
  type        = bool
  description = "False for dev. True for anything with users."
  default     = false
}

variable "backup_retention_period" {
  type    = number
  default = 7
}

variable "deletion_protection" {
  type        = bool
  description = "False for dev. One of the two lines that must flip for staging."
  default     = false
}

variable "skip_final_snapshot" {
  type        = bool
  description = "True for dev. The other one."
  default     = true
}

variable "apply_immediately" {
  type        = bool
  description = "True in dev — nobody is waiting on a maintenance window here."
  default     = true
}
