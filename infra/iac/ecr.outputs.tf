output "ecr_repository_urls" {
<<<<<<< HEAD
  value = { for k, m in module.ecr : k => m.repository_url }
=======
  description = "{ image => repository URL } — what CI tags against"
  value       = { for k, m in module.ecr : k => m.repository_url }
>>>>>>> main
}
