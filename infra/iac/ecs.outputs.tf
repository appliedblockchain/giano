<<<<<<< HEAD
output "ecs_cluster_arn" {
  value = aws_ecs_cluster.ecs.arn
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.ecs.name
}

output "service_discovery_namespace_id" {
  value = aws_service_discovery_private_dns_namespace.ns.id
=======
output "ecs_cluster" {
  description = "the cluster, and the namespace its services resolve each other through"
  value = {
    name                        = aws_ecs_cluster.ecs.name
    arn                         = aws_ecs_cluster.ecs.arn
    service_discovery_namespace = aws_service_discovery_private_dns_namespace.ns.name
  }
>>>>>>> main
}
