# §9.5, D20 — CloudWatch is deliberately almost empty in this deployment. Application logs
# ship via FireLens straight to Datadog and never touch CloudWatch at all. The only groups
# that exist are: each service's log router's own stdout (created inside
# modules/aws/ecs-service/cloudwatch.tf, one per service) and the provision-sponsorship
# one-shot task's plain awslogs group (ecs_tasks_oneshot.tf) — a task that lives forty seconds
# can exit before Fluent Bit has flushed its buffer. Nothing else is declared here.
