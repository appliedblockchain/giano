variable "name" {
  type        = string
  description = "Cluster name, e.g. giano-dev."
}

variable "vpc_id" {
  type        = string
  description = "VPC the Cloud Map private DNS namespace is associated with."
}

variable "service_discovery_namespace" {
  type        = string
  description = "Private DNS namespace, e.g. giano-dev.local."
}

variable "ssm_path_prefix" {
  type        = string
  description = "SSM parameter path this environment's tasks may read, e.g. /giano/dev."
}

variable "container_insights" {
  type        = bool
  description = "Off by default (D12). Costs $10-20/mo in custom metrics when on."
  default     = false
}
