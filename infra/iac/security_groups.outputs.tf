output "alb_sg_id" {
  value = aws_security_group.alb-sg.id
}

output "tasks_sg_id" {
  value = aws_security_group.tasks-sg.id
}

output "bundler_sg_id" {
  value = aws_security_group.bundler-sg.id
}
