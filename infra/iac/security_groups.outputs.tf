output "security_group_ids" {
  description = "the environment's security groups, by role"
  value = {
    alb     = aws_security_group.alb-sg.id
    tasks   = aws_security_group.tasks-sg.id
    bundler = aws_security_group.bundler-sg.id
    app_db  = module.app-db.security_group_id
  }
}
