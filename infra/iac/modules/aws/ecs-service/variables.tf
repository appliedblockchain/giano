# §9.3 — the module that owns the whole path from hostname to container. Target groups and
# listener rules live here, not in alb.tf.

variable "name_prefix" {
  description = "[REQUIRED] e.g. giano-dev"
  type        = string
}

variable "service" {
  description = "[REQUIRED] the service name, e.g. wallet-api"
  type        = string
}

variable "project_name" {
  description = "[REQUIRED] carried into Datadog tags"
  type        = string
}

variable "cluster_arn" {
  description = "[REQUIRED]"
  type        = string
}

variable "cluster_name" {
  description = "[REQUIRED]"
  type        = string
}

variable "aws_region" {
  description = "[REQUIRED]"
  type        = string
}

variable "account_id" {
  description = "[REQUIRED]"
  type        = string
}

variable "image" {
  description = "[REQUIRED] full image ref, repository_url:tag"
  type        = string
}

variable "image_tag" {
  description = "[REQUIRED] the tag alone — DD_VERSION"
  type        = string
}

variable "ecr_repository_arn" {
  description = "[REQUIRED] this service's own ECR repository ARN — the exec role's ECR pull grant is scoped to exactly this"
  type        = string
}

variable "cpu" {
  description = "[REQUIRED] task-level vCPU units, e.g. 512 = 0.5 vCPU"
  type        = number
}

variable "memory" {
  description = "[REQUIRED] task-level memory, MB — app + agent (256) + router (100) + headroom"
  type        = number
}

variable "app_memory" {
  description = "[REQUIRED] the application container's own memory limit, MB"
  type        = number
}

variable "container_port" {
  description = "[REQUIRED]"
  type        = number
}

variable "desired_count" {
  description = "[REQUIRED]"
  type        = number
}

variable "subnet_ids" {
  description = "[REQUIRED] both private subnets"
  type        = list(string)
}

variable "security_group_ids" {
  description = "[REQUIRED]"
  type        = list(string)
}

variable "environment" {
  description = "[OPTIONAL] plain, non-secret environment variables"
  type        = map(string)
  default     = {}
}

variable "secret_arns" {
  description = "[OPTIONAL] { ENV_VAR_NAME => secret ARN } — resolved by the execution role, §7.5"
  type        = map(string)
  default     = {}
}

variable "asm_kms_key_arn" {
  description = "[REQUIRED] the ASM customer-managed KMS key — decrypt is granted only when this service reads a secret"
  type        = string
}

variable "alb_enabled" {
  description = "[REQUIRED] false drops the target group, listener rule and load-balancer block entirely — e.g. bundler"
  type        = bool
}

variable "alb_listener_arn" {
  description = "[OPTIONAL] required when alb_enabled"
  type        = string
  default     = null
}

variable "alb_rule_priority" {
  description = "[OPTIONAL] required when alb_enabled"
  type        = number
  default     = null
}

variable "alb_host_headers" {
  description = "[OPTIONAL] required when alb_enabled. An ALB host condition accepts at most 5 values — a caller whose list grows past that must call this module again at a lower priority against the same target group rather than pass a 6th value here."
  type        = list(string)
  default     = []
}

variable "health_check_path" {
  description = "[OPTIONAL] required when alb_enabled"
  type        = string
  default     = "/"
}

variable "health_check_grace_period_seconds" {
  description = "[OPTIONAL] must outlast the slowest migration when this service carries the init container — §9.6"
  type        = number
  default     = 30
}

variable "vpc_id" {
  description = "[REQUIRED]"
  type        = string
}

variable "service_discovery_id" {
  description = "[REQUIRED] the Cloud Map private DNS namespace id — §9.4"
  type        = string
}

variable "log_retention_in_days" {
  description = "[REQUIRED] retention for the log router's own CloudWatch group — §9.5"
  type        = number
}

variable "enable_execute_command" {
  description = "[REQUIRED] on in dev, off in prd"
  type        = bool
}

# ── Observability — §17.3 ───────────────────────────────────────────────────────────────────
variable "datadog_enabled" {
  description = "[REQUIRED]"
  type        = bool
}

variable "datadog_site" {
  description = "[REQUIRED] e.g. datadoghq.com — must agree with the provider's api_url and FireLens' Host (R16)"
  type        = string
}

variable "datadog_api_key_arn" {
  description = "[REQUIRED] the ASM mirror of the DevOps vault's Datadog API key — §7.4"
  type        = string
}

variable "datadog_source" {
  description = "[REQUIRED] \"nodejs\" or \"nginx\" — selects Datadog's log parsing pipeline"
  type        = string
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
