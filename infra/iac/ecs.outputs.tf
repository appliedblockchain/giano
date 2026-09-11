output "ecs_cluster_arn" {
  value = aws_ecs_cluster.ecs.arn
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.ecs.name
}

output "service_discovery_namespace_id" {
  value = aws_service_discovery_private_dns_namespace.ns.id
}
