<<<<<<< HEAD
# §9.3 — the module that owns the whole path from hostname to container. Target groups and
# listener rules live here, not in alb.tf.

variable "name_prefix" {
  description = "[REQUIRED] e.g. giano-dev"
=======
# --- Identity -------------------------------------------------------------

variable "name_prefix" {
  description = "[REQUIRED] prefix for every resource name, e.g. giano-dev"
>>>>>>> main
  type        = string
}

variable "service" {
<<<<<<< HEAD
  description = "[REQUIRED] the service name, e.g. wallet-api"
=======
  description = "[REQUIRED] service name — the second half of every name, and the Cloud Map hostname"
>>>>>>> main
  type        = string
}

variable "project_name" {
<<<<<<< HEAD
  description = "[REQUIRED] carried into Datadog tags"
  type        = string
}

variable "cluster_arn" {
  description = "[REQUIRED]"
=======
  description = "[REQUIRED] project name, for the Datadog tag set"
  type        = string
}

# --- Cluster and account --------------------------------------------------

variable "cluster_arn" {
  description = "[REQUIRED] ARN of the ECS cluster"
>>>>>>> main
  type        = string
}

variable "cluster_name" {
<<<<<<< HEAD
  description = "[REQUIRED]"
=======
  description = "[REQUIRED] name of the ECS cluster"
>>>>>>> main
  type        = string
}

variable "aws_region" {
<<<<<<< HEAD
  description = "[REQUIRED]"
=======
  description = "[REQUIRED] region, for the log driver and the trust policy condition"
>>>>>>> main
  type        = string
}

variable "account_id" {
<<<<<<< HEAD
  description = "[REQUIRED]"
  type        = string
}

variable "image" {
  description = "[REQUIRED] full image ref, repository_url:tag"
=======
  description = "[REQUIRED] account id, for the confused-deputy conditions on the trust policy (§10.3)"
  type        = string
}

# --- Task -----------------------------------------------------------------

variable "image" {
  description = "[REQUIRED] fully qualified image, including the tag"
>>>>>>> main
  type        = string
}

variable "image_tag" {
<<<<<<< HEAD
  description = "[REQUIRED] the tag alone — DD_VERSION"
  type        = string
}

variable "ecr_repository_arn" {
  description = "[REQUIRED] this service's own ECR repository ARN — the exec role's ECR pull grant is scoped to exactly this"
=======
  description = "[REQUIRED] the tag alone — reported to Datadog as DD_VERSION"
>>>>>>> main
  type        = string
}

variable "cpu" {
<<<<<<< HEAD
  description = "[REQUIRED] task-level vCPU units, e.g. 512 = 0.5 vCPU"
=======
  description = "[REQUIRED] task-level CPU units"
>>>>>>> main
  type        = number
}

variable "memory" {
<<<<<<< HEAD
  description = "[REQUIRED] task-level memory, MB — app + agent (256) + router (100) + headroom"
=======
  description = "[REQUIRED] task-level memory, MB. Double the application's, because of the sidecars (§9.2)"
>>>>>>> main
  type        = number
}

variable "app_memory" {
<<<<<<< HEAD
  description = "[REQUIRED] the application container's own memory limit, MB"
=======
  description = "[REQUIRED] the application container's own hard memory limit, MB"
>>>>>>> main
  type        = number
}

variable "container_port" {
<<<<<<< HEAD
  description = "[REQUIRED]"
=======
  description = "[REQUIRED] the port the application listens on"
>>>>>>> main
  type        = number
}

variable "desired_count" {
<<<<<<< HEAD
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
=======
  description = "[REQUIRED] tasks to run. Ignored after creation — the out-of-hours scheduler owns it (§17.2)"
  type        = number
}

variable "environment" {
  description = "[REQUIRED] plain environment variables. Anything secret belongs in secret_arns"
>>>>>>> main
  type        = map(string)
  default     = {}
}

variable "secret_arns" {
<<<<<<< HEAD
  description = "[OPTIONAL] { ENV_VAR_NAME => secret ARN } — resolved by the execution role, §7.5"
=======
  description = "[REQUIRED] { env var name => Secrets Manager ARN }. The ARN, never the name — Secrets Manager appends a random suffix, so the name is not derivable (§7.5)"
>>>>>>> main
  type        = map(string)
  default     = {}
}

variable "asm_kms_key_arn" {
<<<<<<< HEAD
  description = "[REQUIRED] the ASM customer-managed KMS key — decrypt is granted only when this service reads a secret"
  type        = string
}

# the migrate init container — wallet-api only (§9.6). null for every other service.
variable "init_container" {
  description = "[OPTIONAL] { name, command, secrets } — appended as a non-essential container the app container depends on with condition = SUCCESS"
=======
  description = "[REQUIRED] the ASM customer-managed key the execution role is granted kms:Decrypt on"
  type        = string
}

variable "ecr_repository_arn" {
  description = "[REQUIRED] ARN of THIS service's repository — the execution role's ECR pull is scoped to it and nothing else"
  type        = string
}

variable "init_container" {
  description = "[OPTIONAL] an init container the application waits on with condition=SUCCESS. Set only for wallet-api, which is the only service that touches the database (§9.6)"
>>>>>>> main
  type = object({
    name    = string
    command = list(string)
    secrets = optional(map(string), {})
  })
  default = null
}

<<<<<<< HEAD
variable "alb_enabled" {
  description = "[REQUIRED] false drops the target group, listener rule and load-balancer block entirely — e.g. bundler"
  type        = bool
}

variable "alb_listener_arn" {
  description = "[OPTIONAL] required when alb_enabled"
=======
# --- Network --------------------------------------------------------------

variable "vpc_id" {
  description = "[REQUIRED] VPC the target group lives in"
  type        = string
}

variable "subnet_ids" {
  description = "[REQUIRED] the private subnets. assign_public_ip is false unconditionally — there is no variable for it (§5.2)"
  type        = list(string)
}

variable "security_group_ids" {
  description = "[REQUIRED] security groups for the task ENI"
  type        = list(string)
}

variable "service_discovery_namespace_id" {
  description = "[REQUIRED] Cloud Map private DNS namespace this service registers in (§9.4)"
  type        = string
}

# --- Load balancer --------------------------------------------------------

variable "alb_enabled" {
  description = "[REQUIRED] whether this service gets a target group and a listener rule. false for the bundler, which has no public listener"
  type        = bool
  default     = true
}

variable "alb_listener_arn" {
  description = "[OPTIONAL] the HTTPS listener rules attach to. Required when alb_enabled"
>>>>>>> main
  type        = string
  default     = null
}

variable "alb_rule_priority" {
<<<<<<< HEAD
  description = "[OPTIONAL] required when alb_enabled"
=======
  description = "[OPTIONAL] listener rule priority. Required when alb_enabled"
>>>>>>> main
  type        = number
  default     = null
}

variable "alb_host_headers" {
<<<<<<< HEAD
  description = "[OPTIONAL] required when alb_enabled. An ALB host condition accepts at most 5 values — a caller whose list grows past that must call this module again at a lower priority against the same target group rather than pass a 6th value here."
=======
  description = "[OPTIONAL] the Host values that route here. An ALB host condition accepts at most five values, so a longer list becomes additional rules at descending priority against the same target group (§5.7)"
>>>>>>> main
  type        = list(string)
  default     = []
}

variable "health_check_path" {
<<<<<<< HEAD
  description = "[OPTIONAL] required when alb_enabled"
=======
  description = "[OPTIONAL] target-group health check path"
>>>>>>> main
  type        = string
  default     = "/"
}

<<<<<<< HEAD
variable "health_check_grace_period_seconds" {
  description = "[OPTIONAL] must outlast the slowest migration when this service carries the init container — §9.6"
=======
variable "health_check_matcher" {
  description = "[OPTIONAL] HTTP codes counted as healthy"
  type        = string
  default     = "200"
}

variable "health_check_grace_period_seconds" {
  description = "[OPTIONAL] how long ECS ignores health checks after a task starts. Must outlast the slowest migration where an init container runs one (§9.6, R22)"
  type        = number
  default     = 60
}

variable "deregistration_delay" {
  description = "[OPTIONAL] target deregistration delay. The default of 300 makes every deploy feel broken"
>>>>>>> main
  type        = number
  default     = 30
}

<<<<<<< HEAD
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
=======
# --- Deployment -----------------------------------------------------------

variable "deployment_minimum_healthy_percent" {
  description = "[OPTIONAL] defaults to 100 with an ALB target, 0 without — a single task with no target has nothing to keep healthy while it is replaced"
  type        = number
  default     = null
}

variable "deployment_maximum_percent" {
  description = "[OPTIONAL] defaults to 200 with an ALB target, 100 without"
  type        = number
  default     = null
}

variable "wait_for_steady_state" {
  description = "[OPTIONAL] block the apply until the service stabilises, so a failed deploy fails the workflow"
  type        = bool
  default     = false
}

variable "enable_execute_command" {
  description = "[REQUIRED] `aws ecs execute-command` into a running task — on in dev, off in prd. Developer database access is this, not a bastion (§3.4)"
  type        = bool
}

# --- Observability. §17.3 -------------------------------------------------

variable "datadog_enabled" {
  description = "[REQUIRED] whether the Agent and FireLens sidecars are added. With it off, the application logs to CloudWatch instead"
>>>>>>> main
  type        = bool
}

variable "datadog_site" {
<<<<<<< HEAD
  description = "[REQUIRED] e.g. datadoghq.com — must agree with the provider's api_url and FireLens' Host (R16)"
=======
  description = "[REQUIRED] Datadog site. One variable, because it appears in the provider's api_url, the Agent's DD_SITE and the FireLens Host, and they MUST agree (R16)"
>>>>>>> main
  type        = string
}

variable "datadog_api_key_arn" {
<<<<<<< HEAD
  description = "[REQUIRED] the ASM mirror of the DevOps vault's Datadog API key — §7.4"
=======
  description = "[REQUIRED] ASM ARN of the mirrored Datadog API key. Resolved by the execution role for both sidecars — one secret, one grant, two consumers"
>>>>>>> main
  type        = string
}

variable "datadog_source" {
<<<<<<< HEAD
  description = "[REQUIRED] \"nodejs\" or \"nginx\" — selects Datadog's log parsing pipeline"
  type        = string
}

=======
  description = "[REQUIRED] `nodejs` or `nginx`. Selects Datadog's parsing pipeline — a wrong value means logs arrive as opaque strings with no level and no facets"
  type        = string
}

variable "datadog_agent_image" {
  description = "[OPTIONAL] the Agent image. public.ecr.aws so the pull is same-region and needs no credential"
  type        = string
  default     = "public.ecr.aws/datadog/agent:latest"
}

variable "firelens_image" {
  description = "[OPTIONAL] the log router image — the stock aws-for-fluent-bit build (D20)"
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-for-fluent-bit:stable"
}

variable "log_retention_in_days" {
  description = "[REQUIRED] retention on the one CloudWatch group this service keeps. A Terraform resource rather than ECS auto-creation, because an auto-created group has infinite retention and nothing ever notices"
  type        = number
}

>>>>>>> main
variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
