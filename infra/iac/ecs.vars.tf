# §9.1

variable "ecs_container_insights" {
  description = "disabled everywhere — the Agent covers what happens inside a task, the Datadog AWS integration covers whether the task exists; Container Insights duplicates both and bills CloudWatch custom-metric rates for the privilege (§9.1)"
  type        = map(string)
  default     = { dev = "disabled", stg = "disabled", prd = "disabled" }
}
