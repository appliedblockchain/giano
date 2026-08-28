variable "service_name" {
  type        = string
  description = "Short name, e.g. wallet-api. Becomes the Cloud Map hostname and the log stream prefix."
}

variable "cluster_id" {
  type = string
}

variable "cluster_name" {
  type        = string
  description = "Used to namespace the log group, task family and IAM roles."
}

variable "region" {
  type        = string
  description = "For the awslogs driver."
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type        = list(string)
  description = "Public subnets — tasks need a route to ECR and the chain RPC (D8)."
}

variable "security_group_ids" {
  type = list(string)
}

variable "execution_role_arn" {
  type        = string
  description = "Shared task execution role from the ecs-cluster module."
}

variable "service_discovery_namespace_id" {
  type = string
}

# ── image ──────────────────────────────────────────────────────────────────────────────────

variable "image_url" {
  type        = string
  description = "ECR repository URL, without a tag."
}

variable "image_tag" {
  type        = string
  description = "Commit SHA. Seeds the first task-definition revision; CI owns later ones."
}

# ── sizing ─────────────────────────────────────────────────────────────────────────────────

variable "cpu" {
  type        = number
  description = "Fargate CPU units. 256 = 0.25 vCPU."
  default     = 256
}

variable "memory" {
  type        = number
  description = "MiB. Must be a valid pairing with cpu for Fargate."
  default     = 512
}

variable "desired_count" {
  type        = number
  description = "Initial task count. Ignored on subsequent applies — the scheduler owns it."
  default     = 1
}

# ── configuration ──────────────────────────────────────────────────────────────────────────

variable "environment" {
  type        = map(string)
  description = "Plain environment variables. Never a secret — these are visible in the console."
  default     = {}
}

variable "secrets" {
  type        = map(string)
  description = "Environment variable name => SSM parameter ARN. Resolved at task start."
  default     = {}
}

variable "container_port" {
  type    = number
  default = 8080
}

# ── health ─────────────────────────────────────────────────────────────────────────────────

variable "health_check_command" {
  type        = list(string)
  description = "Container-level health check, e.g. [\"CMD-SHELL\", \"curl -fsS localhost:8080/healthz\"]. Null to omit."
  default     = null
}

variable "health_check_start_period" {
  type        = number
  description = "Grace before container health checks count. wallet-api needs time to connect to Postgres."
  default     = 30
}

variable "health_check_path" {
  type        = string
  description = "ALB target-group health check path. Public services only."
  default     = "/"
}

variable "health_check_grace_period" {
  type        = number
  description = "Seconds the ALB tolerates an unhealthy new task before ECS kills it."
  default     = 60
}

variable "log_retention_days" {
  type        = number
  description = "7 in dev (D12); a dev environment's logs are worthless after a week."
  default     = 7
}

variable "enable_execute_command" {
  type        = bool
  description = "Allow `aws ecs execute-command` into the task. How a developer reaches the database."
  default     = true
}

# ── load balancing ─────────────────────────────────────────────────────────────────────────

variable "alb_host" {
  type        = string
  description = "Hostname to route from, e.g. api.dev.giano.example.com. Null for an internal service."
  default     = null
}

variable "listener_arn" {
  type        = string
  description = "HTTPS listener to attach the host rule to. Required when alb_host is set."
  default     = null
}

variable "listener_priority" {
  type        = number
  description = "Rule priority. Must be unique across the listener."
  default     = null
}
