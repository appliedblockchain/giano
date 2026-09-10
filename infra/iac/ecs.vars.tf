variable "ecs_container_insights" {
  description = "[REQUIRED] Container Insights, per environment. `disabled` everywhere: the Agent covers what happens inside a task and the Datadog AWS integration covers whether the task exists, so Insights sits between the two, duplicates both, and charges CloudWatch custom-metric rates for it (§9.1)"
  type        = map(string)
  default     = { dev = "disabled", stg = "disabled", prd = "disabled" }
}

variable "provision_sponsorship_command" {
  description = "[REQUIRED] the one-shot job's command. Blocked on §16.3 — the e2e script hardcodes the e2e tenants' admin keys and reads e2e/devnet/addresses.json, so it needs generalising to be driven entirely by environment"
  type        = list(string)
  default     = ["node", "dist/provision-sponsorship.js"]
}
