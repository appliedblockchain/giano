# No new variables here — log_retention_in_days (ecs_services.vars.tf) already covers every
# CloudWatch group this deployment creates (the log routers' own stdout, D20, plus the
# provision-sponsorship one-shot task's plain awslogs group, §9.5, §9.7).
