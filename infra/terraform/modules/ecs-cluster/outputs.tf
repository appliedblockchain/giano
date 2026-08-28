output "cluster_id" {
  value = aws_ecs_cluster.this.id
}

output "cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "service_discovery_namespace_id" {
  value = aws_service_discovery_private_dns_namespace.this.id
}

output "service_discovery_namespace" {
  value       = var.service_discovery_namespace
  description = "Suffix for internal hostnames, e.g. wallet-api.giano-dev.local."
}
