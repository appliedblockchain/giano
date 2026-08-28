output "service_name" {
  value = aws_ecs_service.this.name
}

output "service_arn" {
  value = aws_ecs_service.this.id
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.this.arn
}

output "task_role_arn" {
  value       = aws_iam_role.task.arn
  description = "The CI deploy role needs iam:PassRole on this to register new revisions."
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}

output "internal_hostname" {
  value       = aws_service_discovery_service.this.name
  description = "Prefix only; append the Cloud Map namespace."
}
