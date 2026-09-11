output "ecr_repository_urls" {
  value = { for k, m in module.ecr : k => m.repository_url }
}
