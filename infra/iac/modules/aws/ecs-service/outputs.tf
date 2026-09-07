output "service_name" {
  value = aws_ecs_service.svc.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.svc.arn
}

output "task_definition_family" {
  value = aws_ecs_task_definition.svc.family
}

output "execution_role_arn" {
  value = aws_iam_role.exec.arn
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "target_group_arn" {
  description = "null when alb_enabled = false"
  value       = var.alb_enabled ? aws_lb_target_group.svc[0].arn : null
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.log_router.name
}

output "service_discovery_arn" {
  value = aws_service_discovery_service.svc.arn
}
