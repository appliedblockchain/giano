<<<<<<< HEAD
output "alb_sg_id" {
  value = aws_security_group.alb-sg.id
}

output "tasks_sg_id" {
  value = aws_security_group.tasks-sg.id
}

output "bundler_sg_id" {
  value = aws_security_group.bundler-sg.id
=======
output "security_group_ids" {
  description = "the environment's security groups, by role"
  value = {
    alb     = aws_security_group.alb-sg.id
    tasks   = aws_security_group.tasks-sg.id
    bundler = aws_security_group.bundler-sg.id
    app_db  = module.app-db.security_group_id
  }
>>>>>>> main
}
