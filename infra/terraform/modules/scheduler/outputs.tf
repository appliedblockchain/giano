output "role_arn" {
  value = aws_iam_role.this.arn
}

output "schedule_names" {
  value = [for s in aws_scheduler_schedule.this : s.name]
}
