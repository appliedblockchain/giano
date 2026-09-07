output "service_name" {
  description = "name of the ECS service — what the scheduler and the deploy workflow address it by"
  value       = aws_ecs_service.svc.name
}

output "service_arn" {
  description = "ARN of the ECS service"
  value       = aws_ecs_service.svc.id
}

output "task_definition_arn" {
  description = "ARN of the current task definition revision"
  value       = aws_ecs_task_definition.svc.arn
}

output "task_definition_family" {
  description = "task definition family — what `aws ecs list-tasks --family` takes"
  value       = aws_ecs_task_definition.svc.family
}

output "target_group_arn" {
  description = "ARN of the target group, or null for a service with no ALB target"
  value       = var.alb_enabled ? aws_lb_target_group.svc[0].arn : null
}

output "target_group_arn_suffix" {
  description = "the target group's ARN suffix — what a CloudWatch or Datadog `targetgroup:` tag takes, not the full ARN"
  value       = var.alb_enabled ? aws_lb_target_group.svc[0].arn_suffix : null
}

output "exec_role_arn" {
  description = "ARN of the execution role — CI needs iam:PassRole on it (§10.2)"
  value       = module.exec-role.arn
}

output "task_role_arn" {
  description = "ARN of the task role"
  value       = module.task-role.arn
}

output "log_group_name" {
  description = "the service's CloudWatch group — the log router's own stdout while Datadog is enabled"
  value       = aws_cloudwatch_log_group.svc.name
}

output "discovery_hostname" {
  description = "the service's private hostname inside the VPC"
  value       = aws_service_discovery_service.svc.name
}
